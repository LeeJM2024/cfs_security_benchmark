from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import time
from typing import Any

from benchmark_engine.nos3.cosmos_driver import ensure_cmd_tlm_server, run_ruby_script
from benchmark_engine.core.scenario import Scenario, load_scenario


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCENARIO = PROJECT_ROOT / "security_suites" / "ground_system" / "scenarios" / "command_dictionary_pollution.yaml"


class CaseFailure(Exception):
    pass


@dataclass(frozen=True)
class RunConfig:
    container: str
    output_dir: Path
    command_server_root: str
    timeout_seconds: float
    server_timeout_seconds: float
    poll_interval: float
    settle_seconds: float


def main() -> None:
    parser = argparse.ArgumentParser(description="Run live GS-002 COSMOS command dictionary pollution benchmark")
    parser.add_argument("--scenario", type=Path, default=DEFAULT_SCENARIO, help="Path to GS-002 YAML")
    parser.add_argument("--container", help="COSMOS/OpenC3 operator Docker container")
    parser.add_argument("--case", action="append", dest="case_ids", help="Run only this case ID; repeatable")
    parser.add_argument("--include-experimental", action="store_true", help="Include cases not independently live-validated")
    parser.add_argument("--output-dir", type=Path, help="Directory for run artifacts")
    parser.add_argument("--timeout", type=float, default=10.0, help="Post-command observation timeout in seconds")
    parser.add_argument("--server-timeout", type=float, default=60.0, help="CmdTlmServer stop/start timeout in seconds")
    parser.add_argument("--poll-interval", type=float, default=0.5, help="Telemetry polling interval in seconds")
    parser.add_argument("--settle", type=float, default=0.5, help="Delay after telemetry request commands")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print selected cases without modifying a dictionary")
    parser.add_argument(
        "--acknowledge-live-dictionary-pollution",
        action="store_true",
        help="Required for live execution because this temporarily rewrites a COSMOS runtime dictionary",
    )
    args = parser.parse_args()

    scenario = load_scenario(args.scenario)
    if scenario.id.upper() != "GS-002":
        raise SystemExit(f"Expected GS-002 scenario, got {scenario.id}")

    attack = scenario.attack
    config = RunConfig(
        container=args.container or str(attack.get("docker_container", "cosmos-openc3-operator-1")),
        output_dir=args.output_dir or _default_output_dir(scenario),
        command_server_root=str(attack.get("command_server_root", "/home/leejm/nos3/gsw/cosmos")),
        timeout_seconds=args.timeout,
        server_timeout_seconds=args.server_timeout,
        poll_interval=args.poll_interval,
        settle_seconds=args.settle,
    )
    cases = _select_cases(_cases(scenario), args.case_ids, args.include_experimental)
    if not cases:
        raise SystemExit("No GS-002 cases selected.")
    _validate_cases(cases)

    if args.dry_run:
        _print_dry_run(scenario, cases, config)
        return
    if not args.acknowledge_live_dictionary_pollution:
        raise SystemExit("Refusing live dictionary modification without --acknowledge-live-dictionary-pollution")

    config.output_dir.mkdir(parents=True, exist_ok=True)
    initial_server = _wait_for_command_server(config)
    if not initial_server.get("ok"):
        initial_server = ensure_cmd_tlm_server(container=config.container, timeout_seconds=config.server_timeout_seconds)
    if not initial_server.get("ok"):
        _write_json(config.output_dir / "score.json", {"scenario_id": scenario.id, "passed": False, "error": initial_server})
        raise SystemExit(f"CmdTlmServer is not ready: {initial_server.get('error')}")

    results: list[dict[str, Any]] = []
    for case in cases:
        result = _run_case(scenario, case, config)
        results.append(result)
        print(f"{case['id']}: {'PASS' if result['passed'] else 'FAIL'} - {result['reason']}")

    passed = all(result["passed"] for result in results)
    score = {
        "scenario_id": scenario.id,
        "scenario_name": scenario.name,
        "passed": passed,
        "suite_passed": passed,
        "case_count": len(results),
        "passed_case_count": sum(1 for result in results if result["passed"]),
        "cases": results,
        "initial_cmd_tlm_server": initial_server,
        "output_dir": str(config.output_dir),
    }
    _write_json(config.output_dir / "score.json", score)
    (config.output_dir / "summary.md").write_text(_summary_markdown(score), encoding="utf-8")
    print(f"\nGS-002 artifacts written to {config.output_dir}")


def _run_case(scenario: Scenario, case: dict[str, Any], config: RunConfig) -> dict[str, Any]:
    case_id = str(case["id"])
    artifact_dir = config.output_dir / case_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, Any] = {"case_id": case_id, "scenario_id": scenario.id, "started_at": _now_iso()}
    original_text: str | None = None
    original_hash: str | None = None
    mutation_applied = False
    attack_result: dict[str, Any] = {"ok": False, "skipped": True}
    after: dict[str, Any] = {}
    recovery: dict[str, Any] = {"ok": False, "skipped": True}
    failure: str | None = None
    passed = False

    try:
        setup = [_send_command(config.container, command) for command in case.get("setup", [])]
        evidence["setup"] = setup
        if not all(item.get("ok", False) for item in setup):
            raise CaseFailure("setup command failed")

        before = _snapshot(case, config)
        evidence["before"] = before
        if not before.get("ok"):
            raise CaseFailure("failed to collect pre-attack telemetry")

        dictionary_path = str(case["dictionary_path"])
        original_text_result = _read_container_text(config.container, dictionary_path)
        if not original_text_result["ok"]:
            evidence["dictionary_backup"] = original_text_result
            raise CaseFailure("failed to back up runtime dictionary")
        original_text = str(original_text_result["text"])
        original_hash = _sha256_text(original_text)
        backup_path = artifact_dir / Path(dictionary_path).name
        backup_path.write_text(original_text, encoding="utf-8")
        evidence["dictionary_backup"] = {"path": dictionary_path, "sha256": original_hash, "artifact": str(backup_path)}

        mutation = dict(case["mutation"])
        mutation_result = _apply_exact_replacement(original_text, str(mutation["original"]), str(mutation["replacement"]))
        evidence["mutation"] = {key: value for key, value in mutation_result.items() if key != "text"}
        if not mutation_result["ok"]:
            raise CaseFailure("dictionary replacement did not match exactly once")

        write_result = _write_container_text(config.container, dictionary_path, str(mutation_result["text"]))
        evidence["dictionary_write"] = write_result
        if not write_result["ok"]:
            raise CaseFailure("failed to write polluted runtime dictionary")
        mutation_applied = True

        restart_after_mutation = _restart_cmd_tlm_server(config)
        evidence["restart_after_mutation"] = restart_after_mutation
        if not restart_after_mutation["ok"]:
            raise CaseFailure("CmdTlmServer did not recover after dictionary pollution")

        attack_result = _send_command(config.container, str(case["displayed_command"]))
        evidence["attack"] = attack_result
        if not attack_result.get("ok"):
            raise CaseFailure("operator-looking command could not be sent")

        encoded = _read_last_command_buffer(config.container, str(case["displayed_command"]))
        expected_suffix = str(case.get("expected_packet_hex_suffix", "")).lower()
        encoded["expected_packet_hex_suffix"] = expected_suffix
        encoded["matches_expected_suffix"] = bool(encoded.get("packet_hex", "").lower().endswith(expected_suffix))
        evidence["encoded_command"] = encoded
        if not encoded.get("ok") or not encoded["matches_expected_suffix"]:
            raise CaseFailure("sent command buffer did not expose the expected polluted encoding")

        after = _poll_snapshot(case, config, before)
        evidence["after"] = after
        observations = _evaluate_attack(case, before, after)
        evidence["observations"] = observations
        if not observations["passed"]:
            raise CaseFailure(str(observations["reason"]))
        passed = True
        failure = "dictionary pollution caused the configured real effect"
    except CaseFailure as error:
        failure = str(error)
    except Exception as error:  # Keep cleanup and artifacts available for an interrupted live run.
        failure = f"runner exception: {type(error).__name__}: {error}"
        evidence["exception"] = failure
    finally:
        if mutation_applied and original_text is not None:
            restore_write = _write_container_text(config.container, str(case["dictionary_path"]), original_text)
            evidence["dictionary_restore_write"] = restore_write
            restart_after_restore = _restart_cmd_tlm_server(config)
            evidence["restart_after_restore"] = restart_after_restore
            restored = _read_container_text(config.container, str(case["dictionary_path"]))
            restored_hash = _sha256_text(str(restored.get("text", ""))) if restored.get("ok") else None
            dictionary_restored = bool(restore_write.get("ok")) and bool(restored.get("ok")) and restored_hash == original_hash
            evidence["dictionary_restore_verification"] = {
                "read": {key: value for key, value in restored.items() if key != "text"},
                "expected_sha256": original_hash,
                "actual_sha256": restored_hash,
                "matches_backup": dictionary_restored,
            }

            if dictionary_restored and restart_after_restore.get("ok"):
                recovery_commands = [_send_command(config.container, command) for command in case.get("recovery", [])]
                recovered = _snapshot(case, config)
                recovery_effect = _evaluate_recovery(case, recovered)
                recovery = {
                    "commands": recovery_commands,
                    "snapshot": recovered,
                    "effect": recovery_effect,
                    "ok": all(item.get("ok", False) for item in recovery_commands) and recovery_effect["passed"],
                }
            else:
                recovery = {"ok": False, "error": "dictionary restore verification or CmdTlmServer restart failed; recovery command was not sent"}
            evidence["recovery"] = recovery

        evidence["finished_at"] = _now_iso()
        _write_json(artifact_dir / "evidence.json", evidence)
    if mutation_applied and not recovery.get("ok", False):
        passed = False
        failure = f"{failure or 'attack completed'}; dictionary restore or spacecraft recovery failed"
    return _case_result(case, evidence, passed, failure or "case did not complete")


def _apply_exact_replacement(text: str, original: str, replacement: str) -> dict[str, Any]:
    count = text.count(original)
    if count != 1:
        return {"ok": False, "original_match_count": count}
    mutated = text.replace(original, replacement, 1)
    return {
        "ok": True,
        "original_match_count": count,
        "original_sha256": _sha256_text(text),
        "mutated_sha256": _sha256_text(mutated),
        "text": mutated,
    }


def _snapshot(case: dict[str, Any], config: RunConfig) -> dict[str, Any]:
    telemetry = {str(name): str(path) for name, path in dict(case.get("telemetry", {})).items()}
    ruby = f"""
require 'json'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script
requests = {json.dumps(list(case.get('telemetry_requests', [])))}
telemetry = {json.dumps(telemetry)}
begin
  requests.each {{ |request| cmd(request) }}
  sleep({json.dumps(config.settle_seconds)})
  values = {{}}
  telemetry.each {{ |name, path| values[name] = tlm(path) }}
  puts JSON.generate({{ok: true, values: values}})
rescue Exception => error
  puts JSON.generate({{ok: false, error_class: error.class.to_s, error: error.message}})
  exit 3
end
"""
    payload = run_ruby_script(container=config.container, ruby=ruby)
    return {"ok": bool(payload.get("ok")), "values": dict(payload.get("values", {})), "raw": payload}


def _poll_snapshot(case: dict[str, Any], config: RunConfig, before: dict[str, Any]) -> dict[str, Any]:
    deadline = time.monotonic() + config.timeout_seconds
    latest = _snapshot(case, config)
    while time.monotonic() < deadline:
        observations = _evaluate_attack(case, before, latest)
        if observations["passed"]:
            return latest
        time.sleep(config.poll_interval)
        latest = _snapshot(case, config)
    return latest


def _evaluate_attack(case: dict[str, Any], before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    if not after.get("ok"):
        return {"passed": False, "reason": "failed to collect post-attack telemetry"}
    before_values = dict(before.get("values", {}))
    after_values = dict(after.get("values", {}))
    counter_changed = _as_number(after_values.get("cmd_count")) > _as_number(before_values.get("cmd_count"))
    error_unchanged = _values_equal(before_values.get("err_count"), after_values.get("err_count"))
    effect = dict(case["effect"])
    effect_value = after_values.get(str(effect["telemetry"]))
    if effect["type"] == "equals":
        effect_observed = any(_values_equal(effect_value, expected) for expected in effect.get("expected_any", []))
    elif effect["type"] == "changed":
        delta = abs(_as_number(effect_value) - _as_number(before_values.get(str(effect["telemetry"]))))
        effect_observed = delta >= float(effect.get("min_abs_delta", 0))
    else:
        return {"passed": False, "reason": f"unsupported effect type {effect['type']}"}
    passed = counter_changed and error_unchanged and effect_observed
    return {
        "passed": passed,
        "command_counter_increased": counter_changed,
        "error_counter_unchanged": error_unchanged,
        "effect_observed": effect_observed,
        "before": before_values,
        "after": after_values,
        "reason": "observations passed" if passed else "required command counter, error counter, or effect evidence failed",
    }


def _evaluate_recovery(case: dict[str, Any], recovered: dict[str, Any]) -> dict[str, Any]:
    effect = dict(case.get("recovery_effect", {"type": "command_only"}))
    if not recovered.get("ok"):
        return {"passed": False, "reason": "failed to collect recovery telemetry"}
    if effect["type"] == "command_only":
        return {"passed": True, "reason": "recovery command accepted; no reversible state observation is defined"}
    if effect["type"] != "equals":
        return {"passed": False, "reason": f"unsupported recovery effect type {effect['type']}"}
    value = dict(recovered.get("values", {})).get(str(effect["telemetry"]))
    passed = any(_values_equal(value, expected) for expected in effect.get("expected_any", []))
    return {"passed": passed, "telemetry": effect["telemetry"], "value": value, "reason": "recovery observation passed" if passed else "recovery observation failed"}


def _send_command(container: str, command: str) -> dict[str, Any]:
    ruby = f"""
require 'json'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script
command = {json.dumps(command)}
begin
  cmd(command)
  puts JSON.generate({{ok: true, command: command}})
rescue Exception => error
  puts JSON.generate({{ok: false, command: command, error_class: error.class.to_s, error: error.message}})
  exit 3
end
"""
    return run_ruby_script(container=container, ruby=ruby)


def _read_last_command_buffer(container: str, command: str) -> dict[str, Any]:
    target, separator, command_with_parameters = command.partition(" ")
    command_name, _, _ = command_with_parameters.partition(" with ")
    if not separator or not command_name:
        return {"ok": False, "command": command, "error": "expected a COSMOS target followed by a command"}
    ruby = f"""
require 'json'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script
target = {json.dumps(target)}
command_name = {json.dumps(command_name)}
begin
  packet = get_cmd_buffer(target, command_name)
  buffer = packet.respond_to?(:buffer) ? packet.buffer : packet
  bytes = buffer.to_s.b.bytes
  puts JSON.generate({{ok: true, target: target, command: "#{{target}} #{{command_name}}", packet_hex: bytes.pack('C*').unpack1('H*')}})
rescue Exception => error
  puts JSON.generate({{ok: false, command: "#{{target}} #{{command_name}}", error_class: error.class.to_s, error: error.message}})
  exit 3
end
"""
    return run_ruby_script(container=container, ruby=ruby)


def _restart_cmd_tlm_server(config: RunConfig) -> dict[str, Any]:
    commands = [
        "pkill -f '[t]cp://127.0.0.1:7777' || true",
        (
            f"cd {config.command_server_root} && "
            "/usr/bin/ruby tools/CmdTlmServer -c config/tools/cmd_tlm_server/cmd_tlm_server.txt "
            ">/tmp/gs002_cmd_tlm_server.log 2>&1"
        ),
    ]
    results: list[dict[str, Any]] = []
    for index, command in enumerate(commands):
        args = ["docker", "exec"]
        if index == 1:
            args.append("-d")
        args.extend([config.container, "sh", "-lc", command])
        process = subprocess.run(args, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        results.append({"command": command, "returncode": process.returncode, "stdout": process.stdout, "stderr": process.stderr})
        if index == 1 and process.returncode != 0:
            return {"ok": False, "steps": results, "error": "failed to start CmdTlmServer"}
        if index == 0:
            released = _wait_for_command_server_port_release(config)
            results.append({"port_release": released})
            if not released.get("ok"):
                return {"ok": False, "steps": results, "error": released["error"]}
    ready = _wait_for_command_server(config)
    return {"ok": bool(ready.get("ok")), "steps": results, "ready": ready}


def _wait_for_command_server(config: RunConfig) -> dict[str, Any]:
    deadline = time.monotonic() + config.server_timeout_seconds
    probe = "require 'socket'; TCPSocket.new('127.0.0.1', 7777).close"
    while time.monotonic() < deadline:
        process = subprocess.run(
            ["docker", "exec", config.container, "/usr/bin/ruby", "-rsocket", "-e", probe],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.returncode == 0:
            return {"ok": True, "probe": "tcp_connect", "started": True}
        time.sleep(config.poll_interval)
    log = subprocess.run(
        ["docker", "exec", config.container, "sh", "-lc", "tail -80 /tmp/gs002_cmd_tlm_server.log 2>/dev/null || true"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return {
        "ok": False,
        "probe": "tcp_connect",
        "error": "CmdTlmServer did not accept TCP connections on 127.0.0.1:7777 before timeout",
        "stdout": log.stdout,
        "stderr": log.stderr,
    }


def _wait_for_command_server_port_release(config: RunConfig) -> dict[str, Any]:
    deadline = time.monotonic() + config.server_timeout_seconds
    probe = "require 'socket'; server = TCPServer.new('127.0.0.1', 7777); server.close"
    while time.monotonic() < deadline:
        process = subprocess.run(
            ["docker", "exec", config.container, "/usr/bin/ruby", "-rsocket", "-e", probe],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.returncode == 0:
            return {"ok": True, "probe": "tcp_bind", "released": True}
        time.sleep(config.poll_interval)
    return {
        "ok": False,
        "probe": "tcp_bind",
        "error": "CmdTlmServer port 7777 did not become bindable before timeout",
    }


def _read_container_text(container: str, path: str) -> dict[str, Any]:
    process = subprocess.run(
        ["docker", "exec", container, "cat", "--", path],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        return {"ok": False, "path": path, "stderr": process.stderr, "returncode": process.returncode}
    return {"ok": True, "path": path, "text": process.stdout}


def _write_container_text(container: str, path: str, text: str) -> dict[str, Any]:
    process = subprocess.run(
        ["docker", "exec", "-i", container, "sh", "-c", 'cat > "$1"', "sh", path],
        check=False,
        text=True,
        input=text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return {"ok": process.returncode == 0, "path": path, "stderr": process.stderr, "returncode": process.returncode}


def _case_result(case: dict[str, Any], evidence: dict[str, Any], passed: bool, reason: str) -> dict[str, Any]:
    restore = dict(evidence.get("dictionary_restore_verification", {}))
    recovery = dict(evidence.get("recovery", {}))
    return {
        "case_id": str(case["id"]),
        "status": str(case.get("status", "validated")),
        "passed": passed,
        "reason": reason,
        "command_buffer_verified": bool(dict(evidence.get("encoded_command", {})).get("matches_expected_suffix")),
        "dictionary_restored": bool(restore.get("matches_backup")),
        "spacecraft_recovery_attempted": not bool(recovery.get("skipped", False)),
        "spacecraft_recovery_ok": bool(recovery.get("ok")),
    }


def _validate_cases(cases: list[dict[str, Any]]) -> None:
    required = {"id", "dictionary_path", "mutation", "displayed_command", "telemetry", "effect", "recovery"}
    for case in cases:
        missing = sorted(required - set(case))
        if missing:
            raise SystemExit(f"{case.get('id', '<unknown>')} missing required field(s): {', '.join(missing)}")
        mutation = dict(case["mutation"])
        if not mutation.get("original") or not mutation.get("replacement"):
            raise SystemExit(f"{case['id']} mutation must contain non-empty original and replacement text")


def _cases(scenario: Scenario) -> list[dict[str, Any]]:
    cases = scenario.attack.get("cases", [])
    if not isinstance(cases, list):
        raise SystemExit("GS-002 attack.cases must be a list")
    return [dict(case) for case in cases]


def _select_cases(cases: list[dict[str, Any]], selected_ids: list[str] | None, include_experimental: bool) -> list[dict[str, Any]]:
    known = {str(case["id"]): case for case in cases}
    if selected_ids:
        missing = sorted(set(selected_ids) - set(known))
        if missing:
            raise SystemExit(f"Unknown GS-002 case(s): {', '.join(missing)}. Known: {', '.join(sorted(known))}")
        selected = [known[case_id] for case_id in selected_ids]
    else:
        selected = cases
    if include_experimental:
        return selected
    return [case for case in selected if str(case.get("status", "validated")) != "experimental"]


def _print_dry_run(scenario: Scenario, cases: list[dict[str, Any]], config: RunConfig) -> None:
    print(f"GS-002 dry run: {scenario.name}")
    print(f"container: {config.container}")
    print("live flow: backup -> setup -> mutate -> CmdTlmServer restart -> encode check -> send -> observe -> restore -> restart -> recover")
    for case in cases:
        mutation = dict(case["mutation"])
        print(f"\n{case['id']} [{case.get('status', 'validated')}]")
        print(f"  dictionary: {case['dictionary_path']}")
        print(f"  displayed command: {case['displayed_command']}")
        print(f"  exact replacement: {str(mutation['original']).rstrip()!r} -> {str(mutation['replacement']).rstrip()!r}")
        print(f"  expected packet suffix: {case.get('expected_packet_hex_suffix')}")


def _default_output_dir(scenario: Scenario) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return PROJECT_ROOT / "artifacts" / "runs" / f"{stamp}_{scenario.id.lower().replace('-', '')}_command_dictionary_pollution"


def _summary_markdown(score: dict[str, Any]) -> str:
    lines = ["# GS-002 Command Dictionary Pollution", "", f"Suite verdict: **{'PASS' if score['passed'] else 'FAIL'}**", "", "| Case | Verdict | Dictionary restored | Recovery |", "| --- | --- | --- | --- |"]
    for case in score["cases"]:
        lines.append(
            f"| `{case['case_id']}` | `{'PASS' if case['passed'] else 'FAIL'}` | "
            f"`{case['dictionary_restored']}` | `{case['spacecraft_recovery_ok']}` |"
        )
    return "\n".join(lines) + "\n"


def _as_number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("nan")


def _values_equal(left: Any, right: Any) -> bool:
    if left == right:
        return True
    left_number = _as_number(left)
    right_number = _as_number(right)
    if left_number == left_number and right_number == right_number:
        return left_number == right_number
    return str(left).strip().upper() == str(right).strip().upper()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    main()
