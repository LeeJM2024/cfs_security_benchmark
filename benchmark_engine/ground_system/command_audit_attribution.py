from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import time
from typing import Any

from benchmark_engine.nos3.cosmos_driver import ensure_cmd_tlm_server, run_ruby_script
from benchmark_engine.core.scenario import Scenario, load_scenario


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCENARIO = PROJECT_ROOT / "security_suites" / "ground_system" / "scenarios" / "command_audit_attribution.yaml"
TIMESTAMP_PATTERN = re.compile(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d{3}")
ACTOR_PATTERN = re.compile(r"\b(?:actor|principal|operator|user)\s*[=:]", re.IGNORECASE)
SESSION_PATTERN = re.compile(r"\b(?:session|client_id|source)\s*[=:]", re.IGNORECASE)
RESULT_PATTERN = re.compile(r"\b(?:execution_?result|command_?result|result|status)\s*[=:]", re.IGNORECASE)


class CaseFailure(Exception):
    pass


@dataclass(frozen=True)
class RunConfig:
    container: str
    output_dir: Path
    timeout_seconds: float
    poll_interval: float
    settle_seconds: float


def main() -> None:
    parser = argparse.ArgumentParser(description="Run live GS-003 command audit attribution benchmark")
    parser.add_argument("--scenario", type=Path, default=DEFAULT_SCENARIO, help="Path to GS-003 YAML")
    parser.add_argument("--container", help="COSMOS/OpenC3 operator Docker container")
    parser.add_argument("--case", action="append", dest="case_ids", help="Run only this case ID; repeatable")
    parser.add_argument("--output-dir", type=Path, help="Directory for run artifacts")
    parser.add_argument("--timeout", type=float, default=10.0, help="Post-command observation timeout in seconds")
    parser.add_argument("--poll-interval", type=float, default=0.5, help="Telemetry polling interval in seconds")
    parser.add_argument("--settle", type=float, default=0.5, help="Delay after telemetry request commands")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print selected cases without sending a telecommand")
    parser.add_argument(
        "--acknowledge-live-telecommand",
        action="store_true",
        help="Required for live execution because each case sends a real recoverable telecommand",
    )
    args = parser.parse_args()

    scenario = load_scenario(args.scenario)
    if scenario.id.upper() != "GS-003":
        raise SystemExit(f"Expected GS-003 scenario, got {scenario.id}")
    attack = scenario.attack
    config = RunConfig(
        container=args.container or str(attack.get("docker_container", "cosmos-openc3-operator-1")),
        output_dir=args.output_dir or _default_output_dir(scenario),
        timeout_seconds=args.timeout,
        poll_interval=args.poll_interval,
        settle_seconds=args.settle,
    )
    cases = _select_cases(_cases(scenario), args.case_ids)
    _validate_cases(cases)

    if args.dry_run:
        _print_dry_run(scenario, cases, config)
        return
    if not args.acknowledge_live_telecommand:
        raise SystemExit("Refusing live telecommand without --acknowledge-live-telecommand")

    config.output_dir.mkdir(parents=True, exist_ok=True)
    server = ensure_cmd_tlm_server(container=config.container, timeout_seconds=30.0)
    if not server.get("ok"):
        _write_json(config.output_dir / "score.json", {"scenario_id": scenario.id, "benchmark_execution_passed": False, "error": server})
        raise SystemExit(f"CmdTlmServer is not ready: {server.get('error')}")

    results = [_run_case(scenario, case, config) for case in cases]
    execution_passed = all(result["benchmark_execution_passed"] for result in results)
    audit_requirements_met = all(result["audit_requirements_met"] for result in results)
    score = {
        "scenario_id": scenario.id,
        "scenario_name": scenario.name,
        "benchmark_execution_passed": execution_passed,
        "audit_requirements_met": audit_requirements_met,
        "security_verdict": "PROTECTED" if audit_requirements_met else "VULNERABLE",
        "case_count": len(results),
        "cases": results,
        "cmd_tlm_server": server,
        "output_dir": str(config.output_dir),
    }
    _write_json(config.output_dir / "score.json", score)
    (config.output_dir / "summary.md").write_text(_summary_markdown(score), encoding="utf-8")
    for result in results:
        print(
            f"{result['case_id']}: execution={'PASS' if result['benchmark_execution_passed'] else 'FAIL'}; "
            f"audit={'PASS' if result['audit_requirements_met'] else 'FAIL'}; verdict={result['security_verdict']}"
        )
    print(f"\nGS-003 artifacts written to {config.output_dir}")


def _run_case(scenario: Scenario, case: dict[str, Any], config: RunConfig) -> dict[str, Any]:
    case_id = str(case["id"])
    artifact_dir = config.output_dir / case_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, Any] = {"scenario_id": scenario.id, "case_id": case_id, "started_at": _now_iso()}
    execution_passed = False
    reason = "case did not complete"
    recovery: dict[str, Any] = {"ok": False, "skipped": True}

    try:
        setup = [_send_command(config.container, command) for command in case.get("setup", [])]
        evidence["setup"] = setup
        if not all(item.get("ok", False) for item in setup):
            raise CaseFailure("setup command failed")

        before = _snapshot(case, config)
        evidence["before"] = before
        if not before.get("ok"):
            raise CaseFailure("failed to collect pre-command telemetry")

        before_logs = _snapshot_audit_logs(config)
        evidence["audit_before"] = before_logs
        if not before_logs.get("ok"):
            raise CaseFailure("failed to snapshot audit-log locations and offsets")

        command = str(case["command"])
        attack = _send_command(config.container, command)
        evidence["command"] = attack
        if not attack.get("ok"):
            raise CaseFailure("telecommand could not be sent")

        command_buffer = _read_last_command_buffer(config.container, command)
        evidence["command_buffer"] = command_buffer
        after = _poll_snapshot(case, config, before)
        evidence["after"] = after
        execution = _evaluate_execution(case, before, after, command_buffer)
        evidence["execution"] = execution
        execution_passed = execution["passed"]
        reason = execution["reason"]

        audit_after = _snapshot_audit_logs(config)
        evidence["audit_after"] = audit_after
        if not audit_after.get("ok"):
            raise CaseFailure("failed to snapshot audit logs after telecommand")
        audit = _evaluate_audit(case, before_logs, audit_after, command_buffer, config)
        evidence["audit"] = audit
    except CaseFailure as error:
        reason = str(error)
    except Exception as error:
        reason = f"runner exception: {type(error).__name__}: {error}"
        evidence["exception"] = reason
    finally:
        recovery_commands = [_send_command(config.container, command) for command in case.get("recovery", [])]
        recovered = _snapshot(case, config)
        recovery_effect = _evaluate_recovery(case, recovered)
        recovery = {
            "commands": recovery_commands,
            "snapshot": recovered,
            "effect": recovery_effect,
            "ok": all(item.get("ok", False) for item in recovery_commands) and recovery_effect["passed"],
        }
        evidence["recovery"] = recovery
        evidence["finished_at"] = _now_iso()
        _write_json(artifact_dir / "evidence.json", evidence)

    return _finalize_case(case, evidence, execution_passed, recovery, reason)


def _finalize_case(case: dict[str, Any], evidence: dict[str, Any], execution_passed: bool, recovery: dict[str, Any], reason: str) -> dict[str, Any]:
    audit = dict(evidence.get("audit", {}))
    if not recovery.get("ok", False):
        execution_passed = False
        reason = f"{reason}; recovery failed"
    audit_requirements_met = bool(audit.get("requirements_met", False))
    return {
        "case_id": str(case["id"]),
        "benchmark_execution_passed": execution_passed,
        "audit_record_found": bool(audit.get("record_found", False)),
        "audit_requirements_met": audit_requirements_met,
        "missing_audit_fields": list(audit.get("missing_fields", [])),
        "security_verdict": "PROTECTED" if audit_requirements_met else "VULNERABLE",
        "recovery_ok": bool(recovery.get("ok", False)),
        "reason": reason,
    }


def _snapshot_audit_logs(config: RunConfig) -> dict[str, Any]:
    ruby = """
require 'json'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script
begin
  puts JSON.generate({
    ok: true,
    server_messages: get_server_message_log_filename,
    command_log: get_cmd_log_filename
  })
rescue Exception => error
  puts JSON.generate({ok: false, error_class: error.class.to_s, error: error.message})
  exit 3
end
"""
    paths = run_ruby_script(container=config.container, ruby=ruby)
    if not paths.get("ok"):
        return paths
    server_messages = str(paths.get("server_messages", ""))
    command_log = str(paths.get("command_log", ""))
    if not server_messages or not command_log:
        return {"ok": False, "error": "CmdTlmServer did not provide active audit log filenames", "raw": paths}
    return {
        "ok": True,
        "server_messages": _file_offset(config.container, server_messages),
        "command_log": _file_offset(config.container, command_log),
    }


def _file_offset(container: str, path: str) -> dict[str, Any]:
    process = subprocess.run(
        ["docker", "exec", container, "sh", "-c", 'test -f "$1" && wc -c < "$1"', "sh", path],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        offset = int(process.stdout.strip())
    except ValueError:
        return {"ok": False, "path": path, "stderr": process.stderr, "returncode": process.returncode}
    return {"ok": process.returncode == 0, "path": path, "offset": offset}


def _read_log_delta(container: str, before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    if not before.get("ok") or not after.get("ok"):
        return {"ok": False, "error": "audit log offset could not be read"}
    if before["path"] != after["path"]:
        return {"ok": False, "error": "audit log rotated during command", "before": before, "after": after}
    offset = int(before["offset"])
    process = subprocess.run(
        ["docker", "exec", container, "sh", "-c", 'tail -c "+$2" "$1"', "sh", str(before["path"]), str(offset + 1)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return {
        "ok": process.returncode == 0,
        "path": before["path"],
        "before_offset": offset,
        "after_offset": int(after["offset"]),
        "data": process.stdout,
        "stderr": process.stderr.decode("utf-8", errors="replace"),
    }


def _evaluate_audit(
    case: dict[str, Any],
    before: dict[str, Any],
    after: dict[str, Any],
    command_buffer: dict[str, Any],
    config: RunConfig,
) -> dict[str, Any]:
    server_delta = _read_log_delta(config.container, dict(before["server_messages"]), dict(after["server_messages"]))
    command_delta = _read_log_delta(config.container, dict(before["command_log"]), dict(after["command_log"]))
    server_text = bytes(server_delta.get("data", b"")).decode("utf-8", errors="replace")
    required_substrings = [str(value) for value in dict(case["audit_match"]).get("server_message_substrings", [])]
    matching_lines = [line for line in server_text.splitlines() if all(value in line for value in required_substrings)]
    record = matching_lines[-1] if matching_lines else ""
    target, command_name = _command_identity(str(case["command"]))
    packet_hex = str(command_buffer.get("packet_hex", ""))
    packet = bytes.fromhex(packet_hex) if packet_hex and len(packet_hex) % 2 == 0 else b""
    fields = {
        "timestamp": bool(record) and bool(TIMESTAMP_PATTERN.search(record)),
        "target": bool(record) and target in record,
        "command_name": bool(record) and command_name in record,
        "parameters": bool(record) and all(value in record for value in required_substrings[1:]),
        "encoded_packet": bool(packet) and bool(command_delta.get("ok")) and packet in bytes(command_delta.get("data", b"")),
        "actor_identity": bool(record) and bool(ACTOR_PATTERN.search(record)),
        "source_session": bool(record) and bool(SESSION_PATTERN.search(record)),
        "execution_result": bool(record) and bool(RESULT_PATTERN.search(record)),
    }
    requirements = [str(value) for value in case.get("audit_requirements", [])]
    missing = [field for field in requirements if not fields.get(field, False)]
    return {
        "record_found": bool(record),
        "matching_record": record,
        "server_message_delta": _artifact_delta(server_delta, text=True),
        "command_packet_delta": _artifact_delta(command_delta, text=False),
        "fields": fields,
        "requirements": requirements,
        "missing_fields": missing,
        "requirements_met": not missing,
    }


def _command_identity(command: str) -> tuple[str, str]:
    target, separator, command_with_parameters = command.partition(" ")
    command_name, _, _ = command_with_parameters.partition(" with ")
    if not separator or not command_name:
        raise ValueError(f"invalid COSMOS command text: {command}")
    return target, command_name


def _artifact_delta(delta: dict[str, Any], *, text: bool) -> dict[str, Any]:
    result = {key: value for key, value in delta.items() if key != "data"}
    raw = bytes(delta.get("data", b""))
    result["byte_count"] = len(raw)
    result["preview"] = raw.decode("utf-8", errors="replace")[-4000:] if text else raw.hex()
    return result


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
        if _evaluate_execution(case, before, latest, {"ok": True, "packet_hex": "00"})["telemetry_passed"]:
            return latest
        time.sleep(config.poll_interval)
        latest = _snapshot(case, config)
    return latest


def _evaluate_execution(case: dict[str, Any], before: dict[str, Any], after: dict[str, Any], command_buffer: dict[str, Any]) -> dict[str, Any]:
    before_values = dict(before.get("values", {}))
    after_values = dict(after.get("values", {}))
    effect = dict(case["expected_effect"])
    effect_value = after_values.get(str(effect["telemetry"]))
    effect_observed = any(_values_equal(effect_value, value) for value in effect.get("expected_any", []))
    counter_increased = _as_number(after_values.get("cmd_count")) > _as_number(before_values.get("cmd_count"))
    error_unchanged = _values_equal(before_values.get("err_count"), after_values.get("err_count"))
    expected_suffix = str(case.get("expected_packet_hex_suffix", "")).lower()
    buffer_matches = bool(command_buffer.get("packet_hex", "").lower().endswith(expected_suffix))
    telemetry_passed = bool(after.get("ok")) and counter_increased and error_unchanged and effect_observed
    passed = telemetry_passed and bool(command_buffer.get("ok")) and buffer_matches
    return {
        "passed": passed,
        "telemetry_passed": telemetry_passed,
        "command_counter_increased": counter_increased,
        "error_counter_unchanged": error_unchanged,
        "effect_observed": effect_observed,
        "command_buffer_matches": buffer_matches,
        "reason": "real command execution observed" if passed else "command buffer or target execution evidence failed",
    }


def _evaluate_recovery(case: dict[str, Any], recovered: dict[str, Any]) -> dict[str, Any]:
    if not recovered.get("ok"):
        return {"passed": False, "reason": "failed to collect recovery telemetry"}
    effect = dict(case["recovery_effect"])
    value = dict(recovered.get("values", {})).get(str(effect["telemetry"]))
    passed = any(_values_equal(value, expected) for expected in effect.get("expected_any", []))
    return {"passed": passed, "telemetry": effect["telemetry"], "value": value}


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
  puts JSON.generate({{ok: true, packet_hex: buffer.to_s.b.unpack1('H*')}})
rescue Exception => error
  puts JSON.generate({{ok: false, error_class: error.class.to_s, error: error.message}})
  exit 3
end
"""
    return run_ruby_script(container=container, ruby=ruby)


def _cases(scenario: Scenario) -> list[dict[str, Any]]:
    cases = scenario.attack.get("cases", [])
    if not isinstance(cases, list):
        raise SystemExit("GS-003 attack.cases must be a list")
    return [dict(case) for case in cases]


def _select_cases(cases: list[dict[str, Any]], selected_ids: list[str] | None) -> list[dict[str, Any]]:
    known = {str(case["id"]): case for case in cases}
    if not selected_ids:
        return cases
    missing = sorted(set(selected_ids) - set(known))
    if missing:
        raise SystemExit(f"Unknown GS-003 case(s): {', '.join(missing)}. Known: {', '.join(sorted(known))}")
    return [known[case_id] for case_id in selected_ids]


def _validate_cases(cases: list[dict[str, Any]]) -> None:
    required = {"id", "command", "telemetry", "expected_effect", "audit_match", "audit_requirements", "recovery"}
    for case in cases:
        missing = sorted(required - set(case))
        if missing:
            raise SystemExit(f"{case.get('id', '<unknown>')} missing required field(s): {', '.join(missing)}")


def _print_dry_run(scenario: Scenario, cases: list[dict[str, Any]], config: RunConfig) -> None:
    print(f"GS-003 dry run: {scenario.name}")
    print(f"container: {config.container}")
    print("live flow: setup -> snapshot audit-log offsets -> send -> capture log deltas -> evaluate fields -> recover")
    for case in cases:
        print(f"\n{case['id']}")
        print(f"  command: {case['command']}")
        print(f"  required audit fields: {', '.join(case['audit_requirements'])}")


def _default_output_dir(scenario: Scenario) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return PROJECT_ROOT / "artifacts" / "runs" / f"{stamp}_{scenario.id.lower().replace('-', '')}_command_audit_attribution"


def _summary_markdown(score: dict[str, Any]) -> str:
    lines = ["# GS-003 Command Audit Attribution", "", f"Security verdict: **{score['security_verdict']}**", "", "| Case | Command executed | Audit requirements | Missing fields |", "| --- | --- | --- | --- |"]
    for case in score["cases"]:
        lines.append(
            f"| `{case['case_id']}` | `{case['benchmark_execution_passed']}` | `{case['audit_requirements_met']}` | "
            f"{', '.join(case['missing_audit_fields']) or 'none'} |"
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


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    main()
