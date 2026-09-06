"""Sequential SC-APP/SC-ART matrix runner.

Preparation and cleanup remain delegated to the existing track-specific
batch modules.  ``verify`` assumes the selected track has already been
prepared, built, and launched; it only runs the real verifiers in matrix
order and writes an aggregate report.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from benchmark_engine.supply_chain import app_batch, artifact_batch
from benchmark_engine.supply_chain.artifact_runner import run_artifact_profile
from benchmark_engine.supply_chain.runner import run_profile


APP_PROFILE_IDS = ("SC-APP-001", "SC-APP-002", "SC-APP-003", "SC-APP-004", "SC-APP-005")
PAYLOAD_IDS = (
    "SC-PAYLOAD-EXFIL", "SC-PAYLOAD-SP001", "SC-PAYLOAD-SP003",
    "SC-PAYLOAD-SP006", "SC-PAYLOAD-SP007", "SC-PAYLOAD-SP008",
)


def app_cases() -> list[tuple[str, str]]:
    return [(profile_id, payload_id) for profile_id in APP_PROFILE_IDS for payload_id in PAYLOAD_IDS]


def run_verify(
    *, track: str, nos3_root: Path, output_dir: Path, operator_container: str,
    static_delay_ms: int | None = None, trigger_altitude_m: float | None = None,
    destination_ip: str | None = None,
) -> dict[str, Any]:
    reports: list[dict[str, Any]] = []
    total = (30 if track in {"all", "app"} else 0) + (5 if track in {"all", "art"} else 0)
    sequence = 0
    if track in {"all", "app"}:
        for profile_id, payload_id in app_cases():
            sequence += 1
            case_id = f"{profile_id}__{payload_id}"
            _progress(sequence, total, "START", "APP", case_id)
            options: dict[str, Any] = {
                "operator_container": operator_container,
                "payload_id": payload_id,
            }
            if static_delay_ms is not None:
                options["static_delay_ms"] = static_delay_ms
            if trigger_altitude_m is not None:
                options["trigger_altitude_m"] = trigger_altitude_m
            if destination_ip is not None:
                options["destination_ip"] = destination_ip
            try:
                report = run_profile(
                    profile_id, nos3_root=nos3_root,
                    output_dir=output_dir / "app" / case_id,
                    options=options,
                )
            except Exception as error:
                report = {"profile_id": case_id, "passed": False, "error": f"{type(error).__name__}: {error}"}
            passed = bool(report.get("passed"))
            reports.append({"track": "app", "profile_id": case_id, "passed": passed, "report": report})
            _progress(sequence, total, "PASS" if passed else "FAIL", "APP", case_id)

    if track in {"all", "art"}:
        for profile_id in artifact_batch.PROFILE_IDS:
            sequence += 1
            _progress(sequence, total, "START", "ART", profile_id)
            try:
                report = run_artifact_profile(
                    profile_id, nos3_root=nos3_root,
                    output_dir=output_dir / "artifacts",
                    options={"phase": "verify", "operator_container": operator_container},
                )
            except Exception as error:
                report = {"profile_id": profile_id, "passed": False, "error": f"{type(error).__name__}: {error}"}
            passed = bool(report.get("passed"))
            reports.append({"track": "artifact", "profile_id": profile_id, "passed": passed, "report": report})
            _progress(sequence, total, "PASS" if passed else "FAIL", "ART", profile_id)

    result = {
        "phase": "verify",
        "track": track,
        "total": len(reports),
        "passed": sum(1 for item in reports if item["passed"]),
        "failed": sum(1 for item in reports if not item["passed"]),
        "attack_passed": all(item["passed"] for item in reports) if reports else False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "reports": reports,
    }
    _write_report(output_dir, result)
    return result


def _progress(sequence: int, total: int, status: str, track: str, profile_id: str) -> None:
    print(f"[{sequence:02d}/{total:02d}] {status:<5} {track} {profile_id}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the complete SC-APP/SC-ART verification matrix")
    parser.add_argument("--track", choices=("all", "app", "art"), default="all")
    parser.add_argument("--phase", choices=("verify",), default="verify")
    parser.add_argument("--nos3-root", type=Path, default=Path("/home/leejm/nos3"))
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/supply_chain_full"))
    parser.add_argument("--operator-container", default="cosmos-openc3-operator-1")
    parser.add_argument("--static-delay-ms", type=int, default=1000)
    parser.add_argument("--trigger-altitude-m", type=float, default=350000)
    parser.add_argument("--destination-ip")
    args = parser.parse_args()
    result = run_verify(
        track=args.track, nos3_root=args.nos3_root.expanduser().resolve(),
        output_dir=args.output_dir.expanduser().resolve(), operator_container=args.operator_container,
        static_delay_ms=args.static_delay_ms, trigger_altitude_m=args.trigger_altitude_m,
        destination_ip=args.destination_ip,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["attack_passed"] else 1)


def _write_report(output_dir: Path, result: dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "full-batch-report.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
