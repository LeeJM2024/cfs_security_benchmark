from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
from typing import Any

from benchmark_engine.core.scenario import Scenario, load_scenario


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCENARIO = PROJECT_ROOT / "security_suites" / "ground_system" / "scenarios" / "credential_reuse_command_send.yaml"
ADAPTER_PROTOCOL = "gs008_external_json_v1"


@dataclass(frozen=True)
class RunConfig:
    adapter: str
    adapter_command: str | None
    container: str
    output_dir: Path


class AdapterError(Exception):
    pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Run live GS-008 credential reuse command-send benchmark")
    parser.add_argument("--scenario", type=Path, default=DEFAULT_SCENARIO, help="Path to GS-008 YAML")
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
    if scenario.id.upper() != "GS-008":
        raise SystemExit(f"Expected GS-008 scenario, got {scenario.id}")
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
    results = (
        [_run_case(case, config) for case in cases]
        if preflight.get("eligible", False)
        else [_ineligible_result(case, str(preflight.get("reason", "credential/session precondition failed"))) for case in cases]
    )
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
    print(f"\nGS-008 artifacts written to {config.output_dir}")


def _preflight(scenario: Scenario, config: RunConfig) -> dict[str, Any]:
    if config.adapter == "cosmos_legacy":
        return _legacy_cosmos_preflight(scenario, config)
    response = _call_external_adapter(config, {"protocol": ADAPTER_PROTOCOL, "action": "preflight"})
    credential = dict(response.get("credential", {}))
    required = {
        "adapter_ok": bool(response.get("ok")),
        "benchmark_owned_credential": credential.get("benchmark_owned") is True,
        "legitimate_session_authenticated": credential.get("legitimate_session_authenticated") is True,
        "attack_session_authenticated": credential.get("attack_session_authenticated") is True,
        "attack_session_is_distinct": credential.get("attack_session_is_distinct") is True,
        "same_credential_reused": credential.get("same_credential_reused") is True,
    }
    missing = [name for name, met in required.items() if not met]
    return {
        "ok": bool(response.get("ok")),
        "eligible": not missing,
        "reason": "benchmark-owned credential reuse precondition verified" if not missing else f"missing GS-008 precondition(s): {', '.join(missing)}",
        "credential": credential,
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
    directives = [str(value) for value in settings.get("authentication_directives", [])]
    matches = sorted({directive for directive in directives if re.search(rf"^\\s*{re.escape(directive)}\\b", result.stdout, re.IGNORECASE | re.MULTILINE)})
    return {
        "ok": True,
        "eligible": False,
        "reason": "current NOS3/COSMOS CmdTlmServer exposes no verifiable ground credential or authenticated command session; no telecommand was sent",
        "container": config.container,
        "config_path": path,
        "authentication_directives_checked": directives,
        "authentication_directives_found": matches,
        "credential": {"benchmark_owned": False, "legitimate_session_authenticated": False, "attack_session_authenticated": False},
        "config_sha256": hashlib.sha256(result.stdout.encode("utf-8")).hexdigest(),
    }


def _run_case(case: dict[str, Any], config: RunConfig) -> dict[str, Any]:
    case_id = str(case["id"])
    case_dir = config.output_dir / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, Any] = {"case_id": case_id, "started_at": _now_iso()}
    passed = False
    reason = "case did not complete"
    recovery: dict[str, Any] = {"ok": True, "skipped": True}
    try:
        legitimate = _call_external_adapter(config, _request("submit", case, "legitimate_session", "legitimate_session_command"))
        evidence["legitimate_session_submission"] = legitimate
        if not legitimate.get("ok") or legitimate.get("accepted") is not True:
            raise AdapterError("legitimate credential session could not submit the low-risk command")

        before = _call_external_adapter(config, _request("observe", case, "legitimate_session"))
        evidence["before"] = before
        if not before.get("ok"):
            raise AdapterError("adapter could not collect pre-command observations")

        attack = _call_external_adapter(config, _request("submit", case, "reused_credential_attack_session", "attack_session_command"))
        evidence["attack_session_submission"] = attack
        if not attack.get("ok") or attack.get("accepted") is not True:
            raise AdapterError("reused credential was blocked from submitting the critical command")
        if attack.get("step_up_or_approval_challenged") is True:
            raise AdapterError("critical command required a command-specific step-up or approval")

        after = _call_external_adapter(config, _request("observe", case, "reused_credential_attack_session", command_response=attack))
        evidence["after"] = after
        missing = [
            name
            for name, met in {
                "reached_command_buffer": after.get("reached_command_buffer") is True,
                "real_effect_observed": after.get("real_effect_observed") is True,
            }.items()
            if not met
        ]
        if missing:
            raise AdapterError(f"critical command accepted but missing evidence: {', '.join(missing)}")
        passed = True
        reason = "a valid credential was reused from a distinct attack session to release a critical command without a command-specific challenge or approval"
    except (AdapterError, OSError, ValueError) as error:
        reason = str(error)
        evidence["error"] = reason
    finally:
        attack_accepted = bool(dict(evidence.get("attack_session_submission", {})).get("accepted"))
        if attack_accepted:
            try:
                recovery = _call_external_adapter(config, _request("recover", case, "authorized_recovery"))
            except (AdapterError, OSError, ValueError) as error:
                recovery = {"ok": False, "error": str(error)}
        evidence["recovery"] = recovery
        evidence["finished_at"] = _now_iso()
        _write_json(case_dir / "evidence.json", evidence)
    if not recovery.get("ok"):
        passed = False
        reason = f"{reason}; recovery failed"
    return {
        "case_id": case_id,
        "passed": passed,
        "legitimate_session_command_accepted": bool(dict(evidence.get("legitimate_session_submission", {})).get("accepted")),
        "attack_session_command_accepted": bool(dict(evidence.get("attack_session_submission", {})).get("accepted")),
        "step_up_or_approval_challenged": dict(evidence.get("attack_session_submission", {})).get("step_up_or_approval_challenged"),
        "critical_command_reached_command_buffer": bool(dict(evidence.get("after", {})).get("reached_command_buffer")),
        "critical_command_real_effect_observed": bool(dict(evidence.get("after", {})).get("real_effect_observed")),
        "recovery_ok": bool(recovery.get("ok")),
        "reason": reason,
    }


def _request(action: str, case: dict[str, Any], session_context: str, command_key: str | None = None, command_response: dict[str, Any] | None = None) -> dict[str, Any]:
    request: dict[str, Any] = {"protocol": ADAPTER_PROTOCOL, "action": action, "session_context": session_context, "case": case}
    if command_key:
        request["command"] = str(case[command_key])
    if command_response:
        request["command_response"] = command_response
    return request


def _call_external_adapter(config: RunConfig, request: dict[str, Any]) -> dict[str, Any]:
    if not config.adapter_command:
        raise AdapterError("external adapter command is not configured")
    process = subprocess.run(shlex.split(config.adapter_command), input=json.dumps(request), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
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
        "legitimate_session_command_accepted": False,
        "attack_session_command_accepted": False,
        "step_up_or_approval_challenged": None,
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
            raise SystemExit(f"Unknown GS-008 case(s): {', '.join(unknown)}")
        return [by_id[case_id] for case_id in case_ids]
    return cases


def _validate_cases(cases: list[dict[str, Any]]) -> None:
    if not cases:
        raise SystemExit("No GS-008 cases selected.")
    required = {"id", "legitimate_session_command", "attack_session_command", "expected_effect", "recovery_command"}
    for case in cases:
        missing = sorted(required - set(case))
        if missing:
            raise SystemExit(f"{case.get('id', '<unknown>')} missing required field(s): {', '.join(missing)}")


def _print_dry_run(scenario: Scenario, cases: list[dict[str, Any]], config: RunConfig) -> None:
    print(f"{scenario.id} dry run: adapter={config.adapter}")
    for case in cases:
        print(f"{case['id']}: legitimate session={case['legitimate_session_command']}")
        print(f"  reused-credential attack session={case['attack_session_command']}")
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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_output_dir() -> Path:
    return PROJECT_ROOT / "artifacts" / "GS-008" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _summary_markdown(score: dict[str, Any]) -> str:
    lines = [
        "# GS-008 Result",
        "",
        f"Overall: {'PASS' if score['passed'] else 'FAIL'}",
        f"Adapter: `{score['adapter']}`",
        f"Credential/session precondition: {'PASS' if score['precondition_established'] else 'FAIL'}",
        f"Preflight: {score['preflight'].get('reason', '')}",
        "",
        "## Cases",
        "",
    ]
    lines.extend(f"- {case['case_id']}: {'PASS' if case['passed'] else 'FAIL'} - {case['reason']}" for case in score["cases"])
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
