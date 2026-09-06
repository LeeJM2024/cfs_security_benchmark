"""Independent SC-ART transaction batching.

Each child release keeps its own ArtifactTransaction ledger.  The batch adds
target-overlap preflight and reverse-order compensation; it never replaces
the per-profile verification or recovery evidence.
"""
from __future__ import annotations

from pathlib import PurePosixPath, Path
import argparse
import json
from typing import Any, Iterable

from benchmark_engine.supply_chain.artifact_runner import default_manifest_path, run_artifact_profile
from benchmark_engine.supply_chain.release_manifest import load_manifest


PROFILE_IDS = ("SC-ART-001", "SC-ART-002", "SC-ART-003", "SC-ART-004", "SC-ART-005")


class ArtifactBatchError(RuntimeError):
    pass


def preflight(profile_ids: Iterable[str] = PROFILE_IDS) -> dict[str, Any]:
    """Reject exact and ancestor/descendant target collisions before writes."""
    targets: list[tuple[str, str]] = []
    for profile_id in profile_ids:
        manifest = load_manifest(default_manifest_path(profile_id))
        for operation in manifest["operations"]:
            targets.append((profile_id, str(operation["target"])))

    collisions: list[dict[str, str]] = []
    for index, (left_profile, left_target) in enumerate(targets):
        left_path = PurePosixPath(left_target)
        for right_profile, right_target in targets[index + 1:]:
            right_path = PurePosixPath(right_target)
            if left_path == right_path or left_path in right_path.parents or right_path in left_path.parents:
                collisions.append({
                    "left_profile": left_profile, "left_target": left_target,
                    "right_profile": right_profile, "right_target": right_target,
                })
    return {"passed": not collisions, "targets": targets, "collisions": collisions}


def prepare(
    *, nos3_root: Path, output_dir: Path, profile_ids: Iterable[str] = PROFILE_IDS, dry_run: bool = False,
) -> dict[str, Any]:
    selected = tuple(profile_ids)
    check = preflight(selected)
    if not check["passed"]:
        raise ArtifactBatchError(f"SC-ART target overlap detected: {check['collisions']}")
    if dry_run:
        return {"passed": True, "dry_run": True, "preflight": check, "applied_profiles": list(selected)}

    applied: list[str] = []
    reports: list[dict[str, Any]] = []
    try:
        for profile_id in selected:
            report = run_artifact_profile(
                profile_id, nos3_root=nos3_root, output_dir=output_dir, options={"phase": "prepare"},
            )
            deployment = str(report.get("details", {}).get("deployment", ""))
            if deployment not in {"applied", "accepted_by_unprotected_nos3_release_path"}:
                raise ArtifactBatchError(f"{profile_id} was not applied: {deployment or report}")
            applied.append(profile_id)
            reports.append(report)
    except Exception as error:
        compensation = rollback(nos3_root=nos3_root, output_dir=output_dir, profile_ids=reversed(applied))
        raise ArtifactBatchError(f"SC-ART batch prepare failed after {applied}; compensation={compensation}") from error
    return {"passed": True, "preflight": check, "applied_profiles": applied, "reports": reports}


def rollback(
    *, nos3_root: Path, output_dir: Path, profile_ids: Iterable[str] = tuple(reversed(PROFILE_IDS)), dry_run: bool = False,
) -> dict[str, Any]:
    selected = tuple(profile_ids)
    if dry_run:
        return {"passed": True, "dry_run": True, "rollback_profiles": list(selected)}
    reports: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for profile_id in selected:
        try:
            report = run_artifact_profile(
                profile_id, nos3_root=nos3_root, output_dir=output_dir, options={"phase": "rollback"},
            )
            reports.append(report)
            if not bool(report.get("details", {}).get("rollback", {}).get("restored", False)):
                failures.append({"profile_id": profile_id, "report": report})
        except Exception as error:
            failures.append({"profile_id": profile_id, "error": f"{type(error).__name__}: {error}"})
    return {"passed": not failures, "rollback_profiles": list(selected), "reports": reports, "failures": failures}


def main() -> None:
    parser = argparse.ArgumentParser(description="SC-ART-only batch prepare and clean")
    parser.add_argument("--phase", required=True, choices=("prepare", "clean"))
    parser.add_argument("--nos3-root", type=Path, default=Path("/home/leejm/nos3"))
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/supply_chain_sc_art_batch"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.phase == "prepare":
        result = prepare(nos3_root=args.nos3_root, output_dir=args.output_dir, dry_run=args.dry_run)
    else:
        result = rollback(nos3_root=args.nos3_root, output_dir=args.output_dir, dry_run=args.dry_run)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
