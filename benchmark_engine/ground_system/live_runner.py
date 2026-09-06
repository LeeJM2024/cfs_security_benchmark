from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Any

from benchmark_engine.nos3.cosmos_driver import ensure_cmd_tlm_server, run_ruby_script
from benchmark_engine.core.scenario import Scenario, load_scenario


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCENARIO = PROJECT_ROOT / "security_suites" / "ground_system" / "scenarios" / "dangerous_tc_authorization.yaml"
SAFE_FILE_PREFIXES = ("/cf/gs001_", "/tmp/gs001_", "/data/gs001_")
FSW_PATH_MAP = {
    "/cf/": "/home/leejm/nos3/fsw/build/exe/cpu1/cf/",
    "/data/": "/home/leejm/nos3/fsw/build/exe/cpu1/data/",
}
TEMPLATE_PATTERN = re.compile(r"\$\{([^}]+)\}")


@dataclass(frozen=True)
class RunConfig:
    container: str
    fsw_container: str
    output_dir: Path
    timeout_seconds: float
    poll_interval: float
    settle_seconds: float
    dry_run: bool


def main() -> None:
    parser = argparse.ArgumentParser(description="Run live Ground-system GS-001 dangerous TC benchmark")
    parser.add_argument("--scenario", type=Path, default=DEFAULT_SCENARIO, help="Path to GS-001 YAML")
    parser.add_argument("--container", help="COSMOS/OpenC3 operator Docker container")
    parser.add_argument("--fsw-container", help="cFS/NOS3 flight software Docker container for file evidence")
    parser.add_argument("--case", action="append", dest="case_ids", help="Run only this case ID; repeatable")
    parser.add_argument("--output-dir", type=Path, help="Directory for run artifacts")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-case observation timeout in seconds")
    parser.add_argument("--poll-interval", type=float, default=0.5, help="Observation polling interval in seconds")
    parser.add_argument("--settle", type=float, default=0.35, help="Delay after telemetry request commands")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print selected cases without sending commands")
    args = parser.parse_args()

    scenario = load_scenario(args.scenario)
    if scenario.id.upper() != "GS-001":
        raise SystemExit(f"Expected GS-001 scenario, got {scenario.id}")

    attack = scenario.attack
    container = args.container or str(attack.get("docker_container", "cosmos-openc3-operator-1"))
    fsw_container = args.fsw_container or str(attack.get("fsw_container", "sc01-nos-fsw"))
    output_dir = args.output_dir or _default_output_dir(scenario)
    config = RunConfig(
        container=container,
        fsw_container=fsw_container,
        output_dir=output_dir,
        timeout_seconds=args.timeout,
        poll_interval=args.poll_interval,
        settle_seconds=args.settle,
        dry_run=args.dry_run,
    )

    cases = _select_cases(_cases(scenario), args.case_ids)
    if not cases:
        raise SystemExit("No GS-001 cases selected.")

    if args.dry_run:
        _print_dry_run(scenario, cases, config)
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    server = ensure_cmd_tlm_server(container=container)
    if not server.get("ok"):
        _write_json(output_dir / "score.json", {"scenario_id": scenario.id, "passed": False, "error": server})
        raise SystemExit(f"CmdTlmServer is not ready: {server.get('error')}")

    command_log = output_dir / "command_results.jsonl"
    telemetry_before: dict[str, Any] = {}
    telemetry_after: dict[str, Any] = {}
    recovery: dict[str, Any] = {}
    case_results: list[dict[str, Any]] = []

    for case in cases:
        result = _run_case(scenario, case, config, command_log)
        case_id = str(case["id"])
        telemetry_before[case_id] = result["before"]
        telemetry_after[case_id] = result["after"]
        recovery[case_id] = result["recovery"]
        case_results.append(result["score"])
        print(f"{case_id}: {'PASS' if result['score']['passed'] else 'FAIL'} - {result['score']['reason']}")

    passed = all(case["passed"] for case in case_results)
    score = {
        "scenario_id": scenario.id,
        "scenario_name": scenario.name,
        "passed": passed,
        "suite_passed": passed,
        "case_count": len(case_results),
        "passed_case_count": sum(1 for case in case_results if case["passed"]),
        "cases": case_results,
        "cmd_tlm_server": server,
        "output_dir": str(output_dir),
    }
    _write_json(output_dir / "score.json", score)
    _write_json(output_dir / "telemetry_before.json", telemetry_before)
    _write_json(output_dir / "telemetry_after.json", telemetry_after)
    _write_json(output_dir / "recovery.json", recovery)
    (output_dir / "summary.md").write_text(_summary_markdown(scenario, score), encoding="utf-8")
    print(f"\nGS-001 artifacts written to {output_dir}")


def _run_case(scenario: Scenario, case: dict[str, Any], config: RunConfig, command_log: Path) -> dict[str, Any]:
    case_id = str(case["id"])
    missing_env = [name for name in case.get("requires_env", []) if not os.environ.get(str(name))]
    if missing_env:
        score = _case_score(
            scenario,
            case,
            passed=False,
            dangerous_tc_effect_observed=False,
            reason="required safe execution environment variable is missing",
            observations=[{"type": "requires_env", "passed": False, "missing": missing_env}],
            attack_result={"ok": False, "missing_env": missing_env},
            recovery_ok=False,
        )
        score["valid"] = False
        empty = {"ok": False, "reason": "missing_env", "missing_env": missing_env}
        return {"before": empty, "after": empty, "recovery": empty, "score": score}

    context: dict[str, Any] = {"env": dict(os.environ)}
    setup_results = [_run_action(action, config, context) for action in case.get("setup", [])]
    before = _poll_setup_preconditions(case, config) if case.get("setup_observations") else _collect_snapshot(case, config)
    context["before"] = before

    setup_observations = _evaluate_observations(
        case.get("setup_observations", []),
        before,
        before,
        context,
        config=config,
        case=case,
    )
    setup_ok = all(item.get("ok", False) for item in setup_results) and all(
        item["passed"] for item in setup_observations
    )
    if not setup_ok:
        score = _case_score(
            scenario,
            case,
            passed=False,
            dangerous_tc_effect_observed=False,
            reason="setup precondition failed; dangerous TC was not executed",
            observations=setup_observations,
            attack_result={"ok": False, "skipped": True, "reason": "setup precondition failed"},
            recovery_ok=False,
        )
        score["setup"] = setup_results
        score["setup_observations"] = setup_observations
        score["valid"] = False
        return {"before": before, "after": before, "recovery": {"ok": False, "skipped": True}, "score": score}

    command = _render_template(str(case["command"]), context)
    attack_result = _send_command(config.container, command)
    _append_jsonl(command_log, {"case_id": case_id, "phase": "attack", "command": command, "result": attack_result})

    after = _poll_after_attack(case, config, before) if attack_result.get("ok") else _collect_snapshot(case, config)
    context["after"] = after
    observations = _evaluate_observations(case.get("observations", []), before, after, context, config=config, case=case)
    attack_passed = bool(attack_result.get("ok")) and all(item["passed"] for item in observations)

    recovery_results = [_run_action(action, config, context) for action in case.get("recovery", [])]
    time.sleep(config.settle_seconds)
    recovered = _collect_snapshot(case, config)
    context["recovered"] = recovered
    recovery_observations = _evaluate_observations(
        case.get("recovery_observations", []),
        after,
        recovered,
        context,
        config=config,
        case=case,
    )
    recovery_ok = all(item.get("ok", False) for item in recovery_results) and all(
        item["passed"] for item in recovery_observations
    )
    recovery_payload = {
        "actions": recovery_results,
        "snapshot": recovered,
        "observations": recovery_observations,
        "ok": recovery_ok,
    }
    _append_jsonl(command_log, {"case_id": case_id, "phase": "recovery", "result": recovery_payload})

    passed = attack_passed and recovery_ok
    reason = "dangerous TC executed and recovered" if passed else _failure_reason(attack_result, observations, recovery_ok)
    score = _case_score(
        scenario,
        case,
        passed=passed,
        dangerous_tc_effect_observed=attack_passed,
        reason=reason,
        observations=observations,
        attack_result=attack_result,
        recovery_ok=recovery_ok,
    )
    score["setup"] = setup_results
    score["setup_observations"] = setup_observations
    score["valid"] = True
    return {"before": before, "after": after, "recovery": recovery_payload, "score": score}


def _collect_snapshot(case: dict[str, Any], config: RunConfig) -> dict[str, Any]:
    telemetry = _read_cosmos_telemetry(
        container=config.container,
        telemetry=dict(case.get("telemetry", {})),
        requests=list(case.get("telemetry_requests", [])),
        settle_seconds=config.settle_seconds,
    )
    files = {
        name: _docker_file_state(config.fsw_container, path)
        for name, path in dict(case.get("file_checks", {})).items()
    }
    return {
        "ok": bool(telemetry.get("ok")),
        "telemetry": telemetry.get("telemetry", {}),
        "telemetry_requests": telemetry.get("requests", []),
        "telemetry_errors": telemetry.get("errors", []),
        "files": files,
        "captured_at": _now_iso(),
    }


def _poll_after_attack(case: dict[str, Any], config: RunConfig, before: dict[str, Any]) -> dict[str, Any]:
    deadline = time.monotonic() + config.timeout_seconds
    last = _collect_snapshot(case, config)
    context = {"before": before, "after": last, "env": dict(os.environ)}
    while time.monotonic() < deadline:
        observations = _evaluate_observations(case.get("observations", []), before, last, context)
        if all(item["passed"] for item in observations):
            return last
        time.sleep(config.poll_interval)
        last = _collect_snapshot(case, config)
        context["after"] = last
    return last


def _poll_setup_preconditions(case: dict[str, Any], config: RunConfig) -> dict[str, Any]:
    deadline = time.monotonic() + config.timeout_seconds
    last = _collect_snapshot(case, config)
    while time.monotonic() < deadline:
        context = {"before": last, "after": last, "env": dict(os.environ)}
        observations = _evaluate_observations(case.get("setup_observations", []), last, last, context)
        if all(item["passed"] for item in observations):
            return last
        time.sleep(config.poll_interval)
        last = _collect_snapshot(case, config)
    return last


def _read_cosmos_telemetry(
    *,
    container: str,
    telemetry: dict[str, str],
    requests: list[str],
    settle_seconds: float,
) -> dict[str, Any]:
    ruby = _snapshot_ruby(telemetry=telemetry, requests=requests, settle_seconds=settle_seconds)
    return run_ruby_script(container=container, ruby=ruby)


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
  puts JSON.generate({{
    ok: false,
    command: command,
    error_class: error.class.to_s,
    error: error.message,
    backtrace: error.backtrace ? error.backtrace.first(8) : []
  }})
  exit 4
end
"""
    return run_ruby_script(container=container, ruby=ruby)


def _snapshot_ruby(*, telemetry: dict[str, str], requests: list[str], settle_seconds: float) -> str:
    payload = json.dumps({"telemetry": telemetry, "requests": requests, "settle_seconds": settle_seconds})
    return f"""
require 'json'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

config = JSON.parse({json.dumps(payload)})
requests = config.fetch('requests', [])
telemetry = config.fetch('telemetry', {{}})
settle_seconds = config.fetch('settle_seconds', 0.35).to_f

request_results = []
requests.each do |command|
  begin
    cmd(command)
    request_results << {{ok: true, command: command}}
  rescue Exception => error
    request_results << {{ok: false, command: command, error_class: error.class.to_s, error: error.message}}
  end
end
sleep(settle_seconds) if settle_seconds > 0

values = {{}}
errors = []
telemetry.each do |name, path|
  begin
    value = tlm(path)
    values[name] = {{ok: true, path: path, value: value}}
  rescue Exception => error
    values[name] = {{ok: false, path: path, error_class: error.class.to_s, error: error.message}}
    errors << {{name: name, path: path, error_class: error.class.to_s, error: error.message}}
  end
end

puts JSON.generate({{
  ok: errors.empty?,
  telemetry: values,
  requests: request_results,
  errors: errors
}})
"""


def _run_action(action: dict[str, Any], config: RunConfig, context: dict[str, Any]) -> dict[str, Any]:
    action_type = str(action.get("type", ""))
    if action_type == "command":
        command = _render_template(str(action["command"]), context)
        return _send_command(config.container, command)
    if action_type == "file_write":
        return _docker_file_write(config.fsw_container, str(action["path"]), str(action.get("content", "")))
    if action_type == "file_delete":
        return _docker_file_delete(config.fsw_container, str(action["path"]))
    if action_type == "sleep":
        seconds = float(action.get("seconds", config.settle_seconds))
        time.sleep(seconds)
        return {"ok": True, "seconds": seconds}
    return {"ok": False, "error": f"unsupported action type {action_type!r}", "action": action}


def _evaluate_observations(
    observations: list[dict[str, Any]],
    before: dict[str, Any],
    after: dict[str, Any],
    context: dict[str, Any],
    *,
    config: RunConfig | None = None,
    case: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    return [_evaluate_observation(observation, before, after, context, config=config, case=case) for observation in observations]


def _evaluate_observation(
    observation: dict[str, Any],
    before: dict[str, Any],
    after: dict[str, Any],
    context: dict[str, Any],
    *,
    config: RunConfig | None = None,
    case: dict[str, Any] | None = None,
) -> dict[str, Any]:
    obs_type = str(observation["type"])
    name = str(observation.get("name", ""))
    before_value = _telemetry_value(before, name)
    after_value = _telemetry_value(after, name)

    if obs_type == "counter_increased":
        min_delta = float(observation.get("min_delta", 1))
        delta = _numeric_delta(before_value, after_value)
        return _obs_result(observation, delta is not None and delta >= min_delta, before_value, after_value, delta=delta)
    if obs_type == "error_unchanged":
        return _obs_result(observation, _values_equal(before_value, after_value), before_value, after_value)
    if obs_type == "equals":
        expected = _expected_values(observation, context)
        return _obs_result(observation, any(_values_equal(after_value, item) for item in expected), before_value, after_value, expected=expected)
    if obs_type == "changed":
        min_abs_delta = observation.get("min_abs_delta")
        delta = _numeric_delta(before_value, after_value)
        if min_abs_delta is None:
            passed = not _values_equal(before_value, after_value)
        else:
            passed = delta is not None and abs(delta) >= float(min_abs_delta)
        return _obs_result(observation, passed, before_value, after_value, delta=delta)
    if obs_type == "at_least":
        minimum = _render_expected_number(observation.get("min"), context)
        after_number = _as_float(after_value)
        return _obs_result(
            observation,
            after_number is not None and minimum is not None and after_number >= minimum,
            before_value,
            after_value,
            minimum=minimum,
        )
    if obs_type == "unchanged":
        return _obs_result(observation, _values_equal(before_value, after_value), before_value, after_value)
    if obs_type == "file_exists":
        state = _file_state(after, name)
        return _obs_result(observation, bool(state.get("exists")), _file_state(before, name), state)
    if obs_type == "file_missing":
        state = _file_state(after, name)
        return _obs_result(observation, not bool(state.get("exists")), _file_state(before, name), state)
    if obs_type == "file_existed_before":
        state = _file_state(before, name)
        return _obs_result(observation, bool(state.get("exists")), state, _file_state(after, name))
    if obs_type == "file_first_byte_changed":
        before_state = _file_state(before, name)
        after_state = _file_state(after, name)
        return _obs_result(
            observation,
            before_state.get("first_byte") is not None
            and after_state.get("first_byte") is not None
            and not _values_equal(before_state.get("first_byte"), after_state.get("first_byte")),
            before_state,
            after_state,
        )
    if obs_type == "file_first_byte_equals":
        state = _file_state(after, name)
        expected = _expected_values(observation, context)
        return _obs_result(
            observation,
            state.get("first_byte") is not None and any(_values_equal(state.get("first_byte"), item) for item in expected),
            _file_state(before, name),
            state,
            expected=expected,
        )
    return _obs_result(observation, False, before_value, after_value, error=f"unsupported observation type {obs_type!r}")


def _obs_result(
    observation: dict[str, Any],
    passed: bool,
    before_value: Any,
    after_value: Any,
    **extra: Any,
) -> dict[str, Any]:
    result = {
        "type": observation.get("type"),
        "name": observation.get("name"),
        "passed": bool(passed),
        "before": before_value,
        "after": after_value,
    }
    result.update(extra)
    return result


def _case_score(
    scenario: Scenario,
    case: dict[str, Any],
    *,
    passed: bool,
    dangerous_tc_effect_observed: bool,
    reason: str,
    observations: list[dict[str, Any]],
    attack_result: dict[str, Any],
    recovery_ok: bool,
) -> dict[str, Any]:
    return {
        "scenario_id": scenario.id,
        "case_id": case["id"],
        "case_name": case["name"],
        "passed": bool(passed),
        "dangerous_tc_effect_observed": bool(dangerous_tc_effect_observed),
        "reason": reason,
        "attack_command_ok": bool(attack_result.get("ok")),
        "recovery_ok": bool(recovery_ok),
        "observations": observations,
        "security_interpretation": _security_interpretation(
            dangerous_tc_effect_observed=dangerous_tc_effect_observed,
            passed=passed,
        ),
    }


def _security_interpretation(*, dangerous_tc_effect_observed: bool, passed: bool) -> str:
    if passed:
        return "The dangerous TC lacks independent authorization at the ground command interface."
    if dangerous_tc_effect_observed:
        return "The dangerous TC effect was observed, but the benchmark case failed because recovery evidence did not pass."
    return "The dangerous TC was not proven executable with the required evidence."


def _failure_reason(attack_result: dict[str, Any], observations: list[dict[str, Any]], recovery_ok: bool) -> str:
    if not attack_result.get("ok"):
        return "COSMOS command API rejected or failed to send the dangerous TC"
    failed = [str(item.get("name") or item.get("type")) for item in observations if not item.get("passed")]
    if failed:
        return "required execution evidence missing: " + ", ".join(failed)
    if not recovery_ok:
        return "dangerous TC executed but recovery evidence failed"
    return "case did not meet pass criteria"


def _expected_values(observation: dict[str, Any], context: dict[str, Any]) -> list[Any]:
    if "expected_any" in observation:
        return list(observation["expected_any"])
    if "expected" in observation:
        return [observation["expected"]]
    if "expected_env" in observation:
        return [os.environ.get(str(observation["expected_env"]))]
    if "expected_template" in observation:
        return [_render_template(str(observation["expected_template"]), context)]
    return []


def _render_expected_number(value: Any, context: dict[str, Any]) -> float | None:
    if isinstance(value, str):
        value = _render_template(value, context)
    return _as_float(value)


def _telemetry_value(snapshot: dict[str, Any], name: str) -> Any:
    item = snapshot.get("telemetry", {}).get(name, {})
    if isinstance(item, dict) and item.get("ok"):
        return item.get("value")
    return None


def _file_state(snapshot: dict[str, Any], name: str) -> dict[str, Any]:
    state = snapshot.get("files", {}).get(name, {})
    return state if isinstance(state, dict) else {}


def _numeric_delta(before: Any, after: Any) -> float | None:
    before_number = _as_float(before)
    after_number = _as_float(after)
    if before_number is None or after_number is None:
        return None
    return after_number - before_number


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().replace("\x00", "")
    try:
        return float(int(text, 0))
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return None


def _values_equal(left: Any, right: Any) -> bool:
    left_number = _as_float(left)
    right_number = _as_float(right)
    if left_number is not None and right_number is not None:
        return abs(left_number - right_number) < 0.000001
    return _normalize_text(left) == _normalize_text(right)


def _normalize_text(value: Any) -> str:
    return "" if value is None else str(value).replace("\x00", "").strip().upper()


def _docker_file_state(container: str, path: str) -> dict[str, Any]:
    runtime_path = _fsw_runtime_path(path)
    result = _docker_exec(
        container,
        "sh",
        "-lc",
        (
            'p="$1"; '
            'if [ -e "$p" ]; then '
            'kind=file; [ -d "$p" ] && kind=directory; '
            'size=0; [ -f "$p" ] && size=$(wc -c < "$p"); '
            'mode=$(stat -c %a "$p" 2>/dev/null || echo unknown); '
            'first_byte=null; first_bytes_hex=""; '
            'if [ -f "$p" ] && [ "$size" -gt 0 ]; then '
            'first_byte=$(od -An -tu1 -N1 "$p" | tr -d " "); '
            'first_bytes_hex=$(od -An -tx1 -N16 "$p" | tr -d " \\n"); '
            'fi; '
            'printf "{\\"ok\\":true,\\"exists\\":true,\\"kind\\":\\"%s\\",\\"size\\":%s,\\"mode\\":\\"%s\\",\\"path\\":\\"%s\\",\\"first_byte\\":%s,\\"first_bytes_hex\\":\\"%s\\"}\\n" "$kind" "$size" "$mode" "$p" "$first_byte" "$first_bytes_hex"; '
            'else '
            'printf "{\\"ok\\":true,\\"exists\\":false,\\"path\\":\\"%s\\"}\\n" "$p"; '
            "fi"
        ),
        "sh",
        runtime_path,
    )
    payload = _json_or_process_result(result)
    payload["cfe_path"] = path
    payload["runtime_path"] = runtime_path
    return payload


def _docker_file_write(container: str, path: str, content: str) -> dict[str, Any]:
    safe = _safe_file_path(path)
    if not safe:
        return {"ok": False, "path": path, "error": "refusing to write outside GS001 safe file prefixes"}
    runtime_path = _fsw_runtime_path(path)
    result = _docker_exec(
        container,
        "sh",
        "-lc",
        (
            'p="$1"; content="$2"; '
            'mkdir -p "$(dirname "$p")"; '
            'printf "%s\\n" "$content" > "$p"; '
            'printf "{\\"ok\\":true,\\"path\\":\\"%s\\"}\\n" "$p"'
        ),
        "sh",
        runtime_path,
        content,
    )
    payload = _json_or_process_result(result)
    payload["cfe_path"] = path
    payload["runtime_path"] = runtime_path
    return payload


def _docker_file_delete(container: str, path: str) -> dict[str, Any]:
    safe = _safe_file_path(path)
    if not safe:
        return {"ok": False, "path": path, "error": "refusing to delete outside GS001 safe file prefixes"}
    runtime_path = _fsw_runtime_path(path)
    result = _docker_exec(
        container,
        "sh",
        "-lc",
        (
            'p="$1"; '
            'rm -f "$p"; '
            'printf "{\\"ok\\":true,\\"path\\":\\"%s\\"}\\n" "$p"'
        ),
        "sh",
        runtime_path,
    )
    payload = _json_or_process_result(result)
    payload["cfe_path"] = path
    payload["runtime_path"] = runtime_path
    return payload


def _fsw_runtime_path(path: str) -> str:
    for prefix, replacement in FSW_PATH_MAP.items():
        if path.startswith(prefix):
            return replacement + path[len(prefix):]
    return path


def _docker_exec(container: str, *args: str) -> dict[str, Any]:
    result = subprocess.run(
        ["docker", "exec", container, *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return {
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _json_or_process_result(result: dict[str, Any]) -> dict[str, Any]:
    payload = None
    for line in reversed(str(result.get("stdout", "")).splitlines()):
        try:
            payload = json.loads(line)
            break
        except json.JSONDecodeError:
            continue
    if payload is None:
        payload = {"ok": False, "error": "docker action did not emit JSON"}
    payload.setdefault("ok", bool(result.get("ok")))
    payload["process"] = result
    return payload


def _safe_file_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in SAFE_FILE_PREFIXES)


def _render_template(template: str, context: dict[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
        return str(_lookup_template_value(match.group(1), context))

    return TEMPLATE_PATTERN.sub(replace, template)


def _lookup_template_value(key: str, context: dict[str, Any]) -> Any:
    if key.startswith("env."):
        return os.environ.get(key[4:], "")
    if key in os.environ:
        return os.environ[key]
    parts = key.split(".")
    value: Any = context
    for part in parts:
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return ""
    return value


def _cases(scenario: Scenario) -> list[dict[str, Any]]:
    cases = scenario.attack.get("cases", [])
    if not isinstance(cases, list):
        raise SystemExit("GS-001 attack.cases must be a list")
    return [dict(case) for case in cases]


def _select_cases(cases: list[dict[str, Any]], selected_ids: list[str] | None) -> list[dict[str, Any]]:
    if not selected_ids:
        return cases
    wanted = {value.upper() for value in selected_ids}
    selected = [case for case in cases if str(case.get("id", "")).upper() in wanted]
    missing = wanted - {str(case.get("id", "")).upper() for case in selected}
    if missing:
        known = ", ".join(str(case.get("id")) for case in cases)
        raise SystemExit(f"Unknown GS-001 case(s): {', '.join(sorted(missing))}. Known: {known}")
    return selected


def _print_dry_run(scenario: Scenario, cases: list[dict[str, Any]], config: RunConfig) -> None:
    print(f"{scenario.id}: {scenario.name}")
    print(f"container: {config.container}")
    print(f"fsw_container: {config.fsw_container}")
    for case in cases:
        missing_env = [name for name in case.get("requires_env", []) if not os.environ.get(str(name))]
        suffix = f" missing_env={missing_env}" if missing_env else ""
        print(f"- {case['id']} {case['name']}: {case['command']}{suffix}")


def _default_output_dir(scenario: Scenario) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    slug = scenario.name.lower().replace(" ", "_").replace("/", "_")
    return PROJECT_ROOT / "artifacts" / "runs" / f"{stamp}_{scenario.id.lower().replace('-', '')}_{slug}"


def _summary_markdown(scenario: Scenario, score: dict[str, Any]) -> str:
    lines = [
        f"# {scenario.id} {scenario.name}",
        "",
        f"- Suite passed: `{score['suite_passed']}`",
        f"- Cases passed: `{score['passed_case_count']}/{score['case_count']}`",
        "",
        "| Case | Verdict | Reason | Interpretation |",
        "| --- | --- | --- | --- |",
    ]
    for case in score["cases"]:
        verdict = "PASS" if case["passed"] else "FAIL"
        lines.append(
            f"| `{case['case_id']}` | `{verdict}` | {_md_cell(case['reason'])} | "
            f"{_md_cell(case['security_interpretation'])} |"
        )
    lines.append("")
    return "\n".join(lines)


def _md_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _append_jsonl(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(data, ensure_ascii=False, sort_keys=True) + "\n")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    main()
