from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCENARIO_ROOT = PROJECT_ROOT / "security_suites" / "ground_system" / "scenarios"


@dataclass(frozen=True)
class GroundCase:
    scenario_id: str
    scenario_file: str
    module: str
    runner_arguments: tuple[str, ...] = ()


GROUND_CASES = (
    GroundCase("GS-001", "dangerous_tc_authorization.yaml", "benchmark_engine.ground_system.live_runner"),
    GroundCase("GS-002", "command_dictionary_pollution.yaml", "benchmark_engine.ground_system.command_dictionary_pollution"),
    GroundCase("GS-003", "command_audit_attribution.yaml", "benchmark_engine.ground_system.command_audit_attribution"),
    GroundCase(
        "GS-004",
        "ground_configuration_pollution.yaml",
        "benchmark_engine.ground_system.ground_configuration_pollution",
        ("--acknowledge-live-configuration-pollution",),
    ),
    GroundCase(
        "GS-005",
        "command_telemetry_service_dos.yaml",
        "benchmark_engine.ground_system.command_telemetry_service_dos",
        ("--acknowledge-bounded-service-load",),
    ),
    GroundCase("GS-006", "telemetry_display_monitoring_deception.yaml", "benchmark_engine.ground_system.telemetry_display_monitoring_deception"),
    GroundCase("GS-007", "partial_privilege_command_escalation.yaml", "benchmark_engine.ground_system.partial_privilege_command_escalation"),
    GroundCase("GS-008", "credential_reuse_command_send.yaml", "benchmark_engine.ground_system.credential_reuse_command_send"),
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run every registered Ground-system benchmark case sequentially")
    parser.add_argument("--case", action="append", choices=[case.scenario_id for case in GROUND_CASES], help="Run one GS case; repeatable")
    parser.add_argument("--container", help="COSMOS/OpenC3 operator container passed to each compatible case")
    parser.add_argument("--output-dir", type=Path, help="Root directory for per-case artifacts")
    parser.add_argument("--dry-run", action="store_true", help="Validate every selected case without live commands")
    parser.add_argument("--include-experimental", action="store_true", help="Pass the GS002 experimental-case flag")
    args = parser.parse_args()

    selected_ids = set(args.case) if args.case else {case.scenario_id for case in GROUND_CASES}
    output_root = args.output_dir or _default_output_dir()
    output_root.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, object]] = []
    for case in GROUND_CASES:
        if case.scenario_id not in selected_ids:
            continue
        scenario_path = SCENARIO_ROOT / case.scenario_file
        case_output = output_root / case.scenario_id.lower().replace("-", "")
        if not scenario_path.is_file():
            result = {
                "scenario_id": case.scenario_id,
                "status": "UNREGISTERED",
                "passed": False,
                "reason": f"missing scenario definition: {scenario_path}",
            }
            results.append(result)
            print(f"{case.scenario_id}: UNREGISTERED - {result['reason']}")
            continue
        command = [sys.executable, "-m", case.module, "--scenario", str(scenario_path), "--output-dir", str(case_output)]
        if args.container:
            command.extend(["--container", args.container])
        if args.dry_run:
            command.append("--dry-run")
        if args.include_experimental and case.scenario_id == "GS-002":
            command.append("--include-experimental")
        command.extend(case.runner_arguments)

        print(f"\n{case.scenario_id}: {' '.join(command)}")
        completed = subprocess.run(command, check=False)
        results.append(
            {
                "scenario_id": case.scenario_id,
                "status": "COMPLETED" if completed.returncode == 0 else "FAILED",
                "passed": completed.returncode == 0,
                "returncode": completed.returncode,
                "output_dir": str(case_output),
            }
        )

    passed = all(bool(result["passed"]) for result in results)
    summary = {
        "suite": "ground_system",
        "passed": passed,
        "case_count": len(results),
        "passed_case_count": sum(1 for result in results if result["passed"]),
        "results": results,
    }
    (output_root / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nGround-system batch result: {summary['passed_case_count']}/{summary['case_count']} completed successfully")
    print(f"summary: {output_root / 'summary.json'}")
    raise SystemExit(0 if passed else 1)


def _default_output_dir() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return PROJECT_ROOT / "artifacts" / "runs" / f"{stamp}_ground_system_all"


if __name__ == "__main__":
    main()
