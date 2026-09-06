from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any

from benchmark_engine.nos3.cosmos_driver import ensure_cmd_tlm_server, run_ruby_script
from benchmark_engine.core.scenario import Scenario, load_scenario


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCENARIO = PROJECT_ROOT / "security_suites" / "ground_system" / "scenarios" / "telemetry_display_monitoring_deception.yaml"


class CaseFailure(Exception):
    pass


@dataclass(frozen=True)
class RunConfig:
    container: str
    output_dir: Path
    settle_seconds: float
    timeout_seconds: float
    poll_interval: float


def main() -> None:
    parser = argparse.ArgumentParser(description="Run live GS-006 ground telemetry cache replay benchmark")
    parser.add_argument("--scenario", type=Path, default=DEFAULT_SCENARIO, help="Path to GS-006 YAML")
    parser.add_argument("--container", help="COSMOS/OpenC3 operator Docker container")
    parser.add_argument("--case", action="append", dest="case_ids", help="Run only this case ID; repeatable")
    parser.add_argument("--output-dir", type=Path, help="Directory for run artifacts")
    parser.add_argument("--settle", type=float, default=0.5, help="Delay after a real telemetry request")
    parser.add_argument("--timeout", type=float, default=10.0, help="Telemetry convergence timeout")
    parser.add_argument("--poll-interval", type=float, default=0.5, help="Telemetry polling interval")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print selected cases without commanding or injecting telemetry")
    parser.add_argument(
        "--acknowledge-live-telemetry-cache-injection",
        action="store_true",
        help="Required for live execution because this injects a replayed telemetry sample into the COSMOS ground cache",
    )
    args = parser.parse_args()

    scenario = load_scenario(args.scenario)
    if scenario.id.upper() != "GS-006":
        raise SystemExit(f"Expected GS-006 scenario, got {scenario.id}")
    cases = _select_cases(scenario, args.case_ids)
    _validate_cases(cases)
    config = RunConfig(
        container=args.container or str(scenario.attack.get("docker_container", "cosmos-openc3-operator-1")),
        output_dir=args.output_dir or _default_output_dir(),
        settle_seconds=args.settle,
        timeout_seconds=args.timeout,
        poll_interval=args.poll_interval,
    )

    if args.dry_run:
        _print_dry_run(scenario, cases, config)
        return
    if not args.acknowledge_live_telemetry_cache_injection:
        raise SystemExit("Refusing live ground-cache injection without --acknowledge-live-telemetry-cache-injection")

    config.output_dir.mkdir(parents=True, exist_ok=True)
    command_server = ensure_cmd_tlm_server(container=config.container, timeout_seconds=30.0)
    if not command_server.get("ok"):
        _write_json(config.output_dir / "score.json", {"scenario_id": scenario.id, "passed": False, "error": command_server})
        raise SystemExit(f"CmdTlmServer is not ready: {command_server.get('error')}")

    results = [_run_case(scenario, case, config) for case in cases]
    score = {
        "scenario_id": scenario.id,
        "scenario_name": scenario.name,
        "passed": all(item["passed"] for item in results),
        "case_count": len(results),
        "passed_case_count": sum(1 for item in results if item["passed"]),
        "cases": results,
        "cmd_tlm_server": command_server,
        "output_dir": str(config.output_dir),
    }
    _write_json(config.output_dir / "score.json", score)
    (config.output_dir / "summary.md").write_text(_summary_markdown(score), encoding="utf-8")
    for result in results:
        print(f"{result['case_id']}: {'PASS' if result['passed'] else 'FAIL'} - {result['reason']}")
    print(f"\nGS-006 artifacts written to {config.output_dir}")


def _run_case(scenario: Scenario, case: dict[str, Any], config: RunConfig) -> dict[str, Any]:
    case_id = str(case["id"])
    case_dir = config.output_dir / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, Any] = {"scenario_id": scenario.id, "case_id": case_id, "started_at": _now_iso()}
    passed = False
    reason = "case did not complete"
    recovery: dict[str, Any] = {"ok": False, "skipped": True}

    try:
        setup = [_send_command(config.container, command) for command in case.get("setup", [])]
        evidence["setup"] = setup
        if not all(item.get("ok") for item in setup):
            raise CaseFailure("setup command failed")

        baseline = _request_real_snapshot(case, config)
        evidence["baseline"] = baseline
        if not _snapshot_matches(baseline, dict(case["expected_baseline"])):
            raise CaseFailure("configured nominal baseline was not observed before the test")

        attack_command = _send_command(config.container, str(case["real_command"]))
        evidence["real_command"] = attack_command
        if not attack_command.get("ok"):
            raise CaseFailure("real state-changing command could not be sent")

        # This request occurs before the cache injection. Its raw field is the
        # evidence of the actual cFS-generated HK state, not the replayed view.
        trusted_off = _wait_for_real_snapshot(case, config, dict(case["expected_real_state"]), baseline)
        evidence["trusted_pre_injection_observation"] = trusted_off
        if not trusted_off.get("matched"):
            raise CaseFailure("real post-command telemetry did not report the configured changed state before cache injection")
        if not _command_execution_confirmed(baseline, trusted_off):
            raise CaseFailure("real command counter/error-counter evidence was not observed")

        injection = _inject_replayed_sample(case, config, baseline)
        evidence["ground_cache_injection"] = injection
        if not injection.get("ok"):
            raise CaseFailure("COSMOS inject_tlm did not accept the replayed sample")

        operator_view = {
            "ok": bool(injection.get("ok")),
            "observation_basis": "operator_visible_cosmos_latest_value_immediately_after_inject_tlm",
            "converted": injection.get("operator_view_immediate"),
        }
        evidence["operator_view_after_replay"] = operator_view
        if not _snapshot_matches(operator_view, dict(case["expected_replayed_view"]), baseline):
            raise CaseFailure("operator-visible COSMOS value did not change to the replayed baseline value")

        display_reconciled = _wait_for_real_snapshot(case, config, dict(case["expected_real_state"]), baseline)
        evidence["operator_view_after_real_refresh"] = display_reconciled
        if not display_reconciled.get("matched"):
            raise CaseFailure("a fresh real telemetry packet did not restore the ground display to the changed state")
        evidence["operator_view_after_route_settle"] = _operator_view_snapshot(case, config)

        passed = True
        reason = "real telemetry showed the changed state while the injected COSMOS operator view reported a replayed baseline value"
    except CaseFailure as error:
        reason = str(error)
    except Exception as error:
        reason = f"runner exception: {type(error).__name__}: {error}"
        evidence["exception"] = reason
    finally:
        recovery = _recover_case(case, config)
        evidence["recovery"] = recovery
        evidence["finished_at"] = _now_iso()
        _write_json(case_dir / "evidence.json", evidence)

    if not recovery.get("ok"):
        passed = False
        reason = f"{reason}; EPS recovery failed"
    return {
        "case_id": case_id,
        "passed": passed,
        "real_command_executed": _command_execution_confirmed(dict(evidence.get("baseline", {})), dict(evidence.get("trusted_pre_injection_observation", {}))),
        "trusted_pre_injection_changed_state": bool(dict(evidence.get("trusted_pre_injection_observation", {})).get("matched")),
        "operator_view_replayed_baseline": _snapshot_matches(
            dict(evidence.get("operator_view_after_replay", {})),
            dict(case["expected_replayed_view"]),
            dict(evidence.get("baseline", {})),
        ),
        "fresh_real_telemetry_restored_off": bool(dict(evidence.get("operator_view_after_real_refresh", {})).get("matched")),
        "recovery_ok": bool(recovery.get("ok")),
        "reason": reason,
    }


def _request_real_snapshot(case: dict[str, Any], config: RunConfig) -> dict[str, Any]:
    ruby = f"""
require 'json'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script
requests = {json.dumps(_telemetry_requests(case))}
converted_path = {json.dumps(_display_path(case))}
raw_path = converted_path
counter_path = {json.dumps(str(case['telemetry']['cmd_count']))}
error_path = {json.dumps(str(case['telemetry']['err_count']))}
begin
  requests.each {{ |request| cmd(request) }}
  sleep({json.dumps(config.settle_seconds)})
  puts JSON.generate({{
    ok: true,
    observation_basis: 'fresh_real_housekeeping_request_before_or_after_injection',
    converted: tlm(converted_path),
    raw: tlm_raw(raw_path),
    cmd_count: tlm(counter_path),
    err_count: tlm(error_path)
  }})
rescue Exception => error
  puts JSON.generate({{ok: false, error_class: error.class.to_s, error: error.message}})
  exit 3
end
"""
    return run_ruby_script(container=config.container, ruby=ruby)


def _wait_for_real_snapshot(
    case: dict[str, Any], config: RunConfig, expected: dict[str, Any], baseline: dict[str, Any] | None = None
) -> dict[str, Any]:
    deadline = time.monotonic() + config.timeout_seconds
    latest = _request_real_snapshot(case, config)
    while time.monotonic() < deadline:
        if _snapshot_matches(latest, expected, baseline):
            latest["matched"] = True
            return latest
        time.sleep(config.poll_interval)
        latest = _request_real_snapshot(case, config)
    latest["matched"] = _snapshot_matches(latest, expected, baseline)
    return latest


def _operator_view_snapshot(case: dict[str, Any], config: RunConfig) -> dict[str, Any]:
    ruby = f"""
require 'json'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script
converted_path = {json.dumps(_display_path(case))}
begin
  puts JSON.generate({{ok: true, observation_basis: 'operator_visible_cosmos_latest_value', converted: tlm(converted_path)}})
rescue Exception => error
  puts JSON.generate({{ok: false, error_class: error.class.to_s, error: error.message}})
  exit 3
end
"""
    return run_ruby_script(container=config.container, ruby=ruby)


def _inject_replayed_sample(case: dict[str, Any], config: RunConfig, baseline: dict[str, Any]) -> dict[str, Any]:
    injection = dict(case["ground_cache_replay"])
    items = dict(injection.get("items", {}))
    for item_name, baseline_field in dict(injection.get("items_from_baseline", {})).items():
        items[str(item_name)] = baseline[str(baseline_field)]
    ruby = f"""
require 'json'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script
target = {json.dumps(str(injection['target']))}
packet = {json.dumps(str(injection['packet']))}
items = {json.dumps(items)}
operator_path = {json.dumps(_display_path(case))}
begin
  inject_tlm(target, packet, items, :CONVERTED, true, false, false)
  puts JSON.generate({{
    ok: true,
    target: target,
    packet: packet,
    items: items,
    send_routers: true,
    send_packet_log_writers: false,
    create_new_logs: false,
    operator_view_immediate: tlm(operator_path)
  }})
rescue Exception => error
  puts JSON.generate({{ok: false, error_class: error.class.to_s, error: error.message}})
  exit 3
end
"""
    return run_ruby_script(container=config.container, ruby=ruby)


def _recover_case(case: dict[str, Any], config: RunConfig) -> dict[str, Any]:
    commands = [_send_command(config.container, command) for command in case.get("recovery", [])]
    recovered = _wait_for_real_snapshot(case, config, dict(case["expected_baseline"]))
    return {"commands": commands, "snapshot": recovered, "ok": all(item.get("ok") for item in commands) and bool(recovered.get("matched"))}


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


def _snapshot_matches(snapshot: dict[str, Any], expected: dict[str, Any], baseline: dict[str, Any] | None = None) -> bool:
    if not snapshot.get("ok"):
        return False
    if expected.get("converted_equals_baseline"):
        return baseline is not None and _values_equal(snapshot.get("converted"), baseline.get("converted"))
    if expected.get("converted_is_number"):
        return _as_number(snapshot.get("converted")) != float("-inf")
    if "converted_abs_delta_from_baseline_at_least" in expected:
        if baseline is None:
            return False
        delta = abs(_as_number(snapshot.get("converted")) - _as_number(baseline.get("converted")))
        return delta >= float(expected["converted_abs_delta_from_baseline_at_least"])
    converted_matches = _matches_any(snapshot.get("converted"), expected.get("converted_any", []))
    raw_expected = expected.get("raw_any")
    raw_matches = raw_expected is None or _matches_any(snapshot.get("raw"), raw_expected)
    return converted_matches and raw_matches


def _display_path(case: dict[str, Any]) -> str:
    telemetry = dict(case["telemetry"])
    value = telemetry.get("display", telemetry.get("switch0"))
    return "" if value is None else str(value)


def _telemetry_requests(case: dict[str, Any]) -> list[str]:
    if "telemetry_requests" in case:
        return [str(request) for request in case["telemetry_requests"]]
    return [str(case["telemetry_request"])]


def _command_execution_confirmed(before: dict[str, Any], after: dict[str, Any]) -> bool:
    if not before.get("ok") or not after.get("ok"):
        return False
    return _as_number(after.get("cmd_count")) > _as_number(before.get("cmd_count")) and _values_equal(before.get("err_count"), after.get("err_count"))


def _matches_any(actual: Any, expected: Any) -> bool:
    return any(_values_equal(actual, candidate) for candidate in expected)


def _values_equal(left: Any, right: Any) -> bool:
    if left == right:
        return True
    return str(left).strip().upper() == str(right).strip().upper()


def _as_number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("-inf")


def _select_cases(scenario: Scenario, case_ids: list[str] | None) -> list[dict[str, Any]]:
    cases = [dict(item) for item in scenario.attack.get("cases", [])]
    by_id = {str(case["id"]): case for case in cases}
    if case_ids:
        unknown = [case_id for case_id in case_ids if case_id not in by_id]
        if unknown:
            raise SystemExit(f"Unknown GS-006 case(s): {', '.join(unknown)}")
        return [by_id[case_id] for case_id in case_ids]
    return cases


def _validate_cases(cases: list[dict[str, Any]]) -> None:
    if not cases:
        raise SystemExit("No GS-006 cases selected.")
    required = {"id", "setup", "telemetry", "real_command", "expected_baseline", "expected_real_state", "ground_cache_replay", "expected_replayed_view", "recovery"}
    for case in cases:
        missing = sorted(required - set(case))
        if missing:
            raise SystemExit(f"{case.get('id', '<unknown>')} missing required field(s): {', '.join(missing)}")
        if "telemetry_request" not in case and "telemetry_requests" not in case:
            raise SystemExit(f"{case['id']} requires telemetry_request or telemetry_requests")
        if not _display_path(case):
            raise SystemExit(f"{case['id']} telemetry requires a display field")


def _print_dry_run(scenario: Scenario, cases: list[dict[str, Any]], config: RunConfig) -> None:
    print(f"{scenario.id} dry run: COSMOS container={config.container}")
    for case in cases:
        replay = dict(case["ground_cache_replay"])
        print(f"{case['id']}: real command={case['real_command']}")
        items = dict(replay.get("items", {}))
        if replay.get("items_from_baseline"):
            items["<from_baseline>"] = dict(replay["items_from_baseline"])
        print(f"  inject_tlm({replay['target']}, {replay['packet']}, {items})")
        print("  injection routes to COSMOS latest telemetry but does not write telemetry packet logs")


def _default_output_dir() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return PROJECT_ROOT / "artifacts" / "runs" / f"{stamp}_gs006_telemetry_display_monitoring_deception"


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _summary_markdown(score: dict[str, Any]) -> str:
    lines = ["# GS-006 Telemetry Cache Replay", "", f"Suite result: **{'PASS' if score['passed'] else 'FAIL'}**", ""]
    for case in score["cases"]:
        lines.append(f"- `{case['case_id']}`: **{'PASS' if case['passed'] else 'FAIL'}** - {case['reason']}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
