from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shlex
import subprocess
from typing import Any

from benchmark_engine.core.scenario import Scenario, load_scenario


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCENARIO = PROJECT_ROOT / "security_suites" / "ground_system" / "scenarios" / "partial_privilege_command_escalation.yaml"
ADAPTER_PROTOCOL = "gs007_external_json_v1"


@dataclass(frozen=True)
class RunConfig:
    adapter: str
    adapter_command: str | None
    container: str
    output_dir: Path


class AdapterError(Exception):
    pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Run live GS-007 partial-privilege command escalation benchmark")
    parser.add_argument("--scenario", type=Path, default=DEFAULT_SCENARIO, help="Path to GS-007 YAML")
    parser.add_argument("--adapter", choices=("cosmos_legacy", "external_json"), default="cosmos_legacy")
    parser.add_argument("--adapter-command", help="External JSON adapter command; required for external_json")
    parser.add_argument("--container", help="COSMOS/OpenC3 operator container for cosmos_legacy preflight")
    parser.add_argument("--case", action="append", dest="case_ids", help="Run only this case ID; repeatable")
    parser.add_argument("--output-dir", type=Path, help="Directory for run artifacts")
    parser.add_argument("--dry-run", action="store_true", help="Validate configuration without contacting a target")
    parser.add_argument(
        "--acknowledge-live-telecommand",
        action="store_true",
        help="Required for external_json because a configured adapter may send real recoverable telecommands",
    )
    args = parser.parse_args()

    scenario = load_scenario(args.scenario)
    if scenario.id.upper() != "GS-007":
        raise SystemExit(f"Expected GS-007 scenario, got {scenario.id}")
    cases = _select_cases(scenario, args.case_ids)
    _validate_cases(cases)
    config = RunConfig(
        adapter=args.adapter,
        adapter_command=args.adapter_command,
        container=args.container or str(dict(scenario.attack.get("legacy_cosmos_preflight", {})).get("docker_container", "cosmos-openc3-operator-1")),
        output_dir=args.output_dir or _default_output_dir(),
    )
    if config.adapter == "external_json" and not config.adapter_command:
        raise SystemExit("--adapter-command is required with --adapter external_json")
    if args.dry_run:
        _print_dry_run(scenario, cases, config)
        return
    if config.adapter == "external_json" and not args.acknowledge_live_telecommand:
        raise SystemExit("Refusing external adapter execution without --acknowledge-live-telecommand")

    config.output_dir.mkdir(parents=True, exist_ok=True)
    preflight = _preflight(scenario, config)
    _write_json(config.output_dir / "preflight.json", preflight)
    if not preflight.get("eligible", False):
        results = [_ineligible_result(case, str(preflight.get("reason", "role-bound identity precondition failed"))) for case in cases]
    else:
        results = [_run_case(case, config) for case in cases]

    score = {
        "scenario_id": scenario.id,
        "scenario_name": scenario.name,
        "passed": all(item["passed"] for item in results),
        "adapter": config.adapter,
        "precondition_established": bool(preflight.get("eligible", False)),
        "preflight": preflight,
        "case_count": len(results),
        "passed_case_count": sum(1 for item in results if item["passed"]),
        "cases": results,
        "output_dir": str(config.output_dir),
    }
    _write_json(config.output_dir / "score.json", score)
    (config.output_dir / "summary.md").write_text(_summary_markdown(score), encoding="utf-8")
    for result in results:
        print(f"{result['case_id']}: {'PASS' if result['passed'] else 'FAIL'} - {result['reason']}")
    print(f"\nGS-007 artifacts written to {config.output_dir}")


def _preflight(scenario: Scenario, config: RunConfig) -> dict[str, Any]:
    if config.adapter == "cosmos_legacy":
        return _legacy_cosmos_preflight(scenario, config)
    response = _call_external_adapter(config, {"protocol": ADAPTER_PROTOCOL, "action": "preflight"})
    identity = dict(response.get("identity", {}))
    required = {
        "adapter_ok": bool(response.get("ok")),
        "authenticated_identity": bool(identity.get("authenticated")) and bool(identity.get("id")),
        "non_administrative_role": bool(identity.get("role")) and not bool(identity.get("administrative", False)),
        "low_risk_command_allowed": response.get("low_risk_command_allowed") is True,
        "critical_command_denied_by_declared_policy": response.get("critical_command_denied_by_declared_policy") is True,
    }
    missing = [name for name, met in required.items() if not met]
    return {
        "ok": bool(response.get("ok")),
        "eligible": not missing,
        "reason": "role-bound low-privilege identity verified" if not missing else f"missing GS-007 precondition(s): {', '.join(missing)}",
        "identity": identity,
        "requirements": required,
        "adapter_response": response,
    }


def _legacy_cosmos_preflight(scenario: Scenario, config: RunConfig) -> dict[str, Any]:
    settings = dict(scenario.attack.get("legacy_cosmos_preflight", {}))
    path = str(settings["command_server_config"])
    result = subprocess.run(
        ["docker", "exec", config.container, "cat", path],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        return {
            "ok": False,
            "eligible": False,
            "reason": f"could not read active CmdTlmServer configuration: {result.stderr.strip() or 'docker exec failed'}",
            "container": config.container,
            "config_path": path,
        }
    directives = [str(value) for value in settings.get("role_policy_directives", [])]
    matches = sorted({directive for directive in directives if re.search(rf"^\\s*{re.escape(directive)}\\b", result.stdout, re.IGNORECASE | re.MULTILINE)})
    return {
        "ok": True,
        "eligible": False,
        "reason": "current NOS3/COSMOS CmdTlmServer exposes no verifiable authenticated low-privilege role boundary; no telecommand was sent",
        "container": config.container,
        "config_path": path,
        "role_policy_directives_checked": directives,
        "role_policy_directives_found": matches,
        "identity": {"authenticated": False, "id": None, "role": None},
        "config_sha256": _sha256_text(result.stdout),
    }


def _run_case(case: dict[str, Any], config: RunConfig) -> dict[str, Any]:
    case_id = str(case["id"])
    case_dir = config.output_dir / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, Any] = {"case_id": case_id, "started_at": _now_iso()}
    passed = False
    reason = "case did not complete"
    recovery: dict[str, Any] = {"ok": False, "skipped": True}
    try:
        low_risk = _call_external_adapter(config, _request("submit", case, command_key="low_risk_command"))
        evidence["low_risk_submission"] = low_risk
        if not low_risk.get("ok") or low_risk.get("accepted") is not True:
            raise AdapterError("authenticated low-risk command was not accepted")

        before = _call_external_adapter(config, _request("observe", case))
        evidence["before"] = before
        if not before.get("ok"):
            raise AdapterError("adapter could not collect pre-command observations")

        critical = _call_external_adapter(config, _request("submit", case, command_key="privileged_command"))
        evidence["critical_submission"] = critical
        if not critical.get("ok") or critical.get("accepted") is not True:
            raise AdapterError("critical command was rejected by the role policy")

        after = _call_external_adapter(config, _request("observe", case, command_response=critical))
        evidence["after"] = after
        required = {
            "reached_command_buffer": after.get("reached_command_buffer") is True,
            "real_effect_observed": after.get("real_effect_observed") is True,
        }
        missing = [name for name, met in required.items() if not met]
        if missing:
            raise AdapterError(f"critical command accepted but missing evidence: {', '.join(missing)}")
        passed = True
        reason = "authenticated low-privilege identity submitted a policy-denied critical command that reached the command buffer and produced the configured real effect"
    except (AdapterError, OSError, ValueError) as error:
        reason = str(error)
        evidence["error"] = reason
    finally:
        critical_submitted = bool(dict(evidence.get("critical_submission", {})).get("accepted"))
        if critical_submitted:
            try:
                recovery = _call_external_adapter(config, _request("recover", case))
            except (AdapterError, OSError, ValueError) as error:
                recovery = {"ok": False, "error": str(error)}
        else:
            recovery = {"ok": True, "skipped": True, "reason": "critical command was not accepted"}
        evidence["recovery"] = recovery
        evidence["finished_at"] = _now_iso()
        _write_json(case_dir / "evidence.json", evidence)
    if not recovery.get("ok"):
        passed = False
        reason = f"{reason}; recovery failed"
    return {
        "case_id": case_id,
        "passed": passed,
        "low_risk_command_accepted": bool(dict(evidence.get("low_risk_submission", {})).get("accepted")),
        "critical_command_accepted": bool(dict(evidence.get("critical_submission", {})).get("accepted")),
        "critical_command_reached_command_buffer": bool(dict(evidence.get("after", {})).get("reached_command_buffer")),
        "critical_command_real_effect_observed": bool(dict(evidence.get("after", {})).get("real_effect_observed")),
        "recovery_ok": bool(recovery.get("ok")),
        "reason": reason,
    }


def _request(action: str, case: dict[str, Any], *, command_key: str | None = None, command_response: dict[str, Any] | None = None) -> dict[str, Any]:
    request: dict[str, Any] = {"protocol": ADAPTER_PROTOCOL, "action": action, "case": case}
    if command_key:
        request["command"] = str(case[command_key])
    if command_response:
        request["command_response"] = command_response
    return request


def _call_external_adapter(config: RunConfig, request: dict[str, Any]) -> dict[str, Any]:
    if not config.adapter_command:
        raise AdapterError("external adapter command is not configured")
    process = subprocess.run(
        shlex.split(config.adapter_command),
        input=json.dumps(request),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    payload = _last_json_line(process.stdout)
    if payload is None:
        raise AdapterError(f"external adapter did not emit JSON (exit {process.returncode}): {process.stderr.strip()}")
    if process.returncode != 0:
        payload.setdefault("ok", False)
        payload.setdefault("adapter_stderr", process.stderr)
    return payload


def _ineligible_result(case: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "case_id": str(case["id"]),
        "passed": False,
        "low_risk_command_accepted": False,
        "critical_command_accepted": False,
        "critical_command_reached_command_buffer": False,
        "critical_command_real_effect_observed": False,
        "recovery_ok": True,
        "recovery_skipped": True,
        "reason": reason,
    }


def _select_cases(scenario: Scenario, case_ids: list[str] | None) -> list[dict[str, Any]]:
    cases = [dict(item) for item in scenario.attack.get("cases", [])]
    by_id = {str(case["id"]): case for case in cases}
    if case_ids:
        unknown = [case_id for case_id in case_ids if case_id not in by_id]
        if unknown:
            raise SystemExit(f"Unknown GS-007 case(s): {', '.join(unknown)}")
        return [by_id[case_id] for case_id in case_ids]
    return cases


def _validate_cases(cases: list[dict[str, Any]]) -> None:
    if not cases:
        raise SystemExit("No GS-007 cases selected.")
    required = {"id", "low_risk_command", "privileged_command", "expected_effect", "recovery_command"}
    for case in cases:
        missing = sorted(required - set(case))
        if missing:
            raise SystemExit(f"{case.get('id', '<unknown>')} missing required field(s): {', '.join(missing)}")


def _print_dry_run(scenario: Scenario, cases: list[dict[str, Any]], config: RunConfig) -> None:
    print(f"{scenario.id} dry run: adapter={config.adapter}")
    for case in cases:
        print(f"{case['id']}: low-risk={case['low_risk_command']}")
        print(f"  policy-denied critical={case['privileged_command']}")
    if config.adapter == "cosmos_legacy":
        print("cosmos_legacy is preflight-only and never sends a telecommand.")
    else:
        print(f"external adapter command: {config.adapter_command}")


def _last_json_line(stdout: str) -> dict[str, Any] | None:
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        return value if isinstance(value, dict) else None
    return None


def _sha256_text(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_output_dir() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return PROJECT_ROOT / "artifacts" / "GS-007" / stamp


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _summary_markdown(score: dict[str, Any]) -> str:
    lines = [
        "# GS-007 Result",
        "",
        f"Overall: {'PASS' if score['passed'] else 'FAIL'}",
        f"Adapter: `{score['adapter']}`",
        f"Role-bound identity precondition: {'PASS' if score['precondition_established'] else 'FAIL'}",
        f"Preflight: {score['preflight'].get('reason', '')}",
        "",
        "## Cases",
        "",
    ]
    lines.extend(f"- {case['case_id']}: {'PASS' if case['passed'] else 'FAIL'} - {case['reason']}" for case in score["cases"])
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
