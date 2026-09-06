"""Combined, source-tree-only SC-APP + SC-ART preparation and cleanup.

This is intentionally an orchestration layer.  It does not build or launch
NOS3, and it does not perform a CmdTlmServer action.  The caller performs one
normal NOS3 build/relaunch between ``prepare`` and verification, and another
after ``clean``.  GS verifiers retain their own automatic CmdTlmServer reload.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from benchmark_engine.supply_chain import app_batch, artifact_batch


DEFAULT_OUTPUT_DIR = Path("artifacts/supply_chain_batch")
LEDGER_NAME = "batch-ledger.json"


def run_batch(
    *, phase: str, nos3_root: Path, output_dir: Path, prepare_valid_novatel: bool = True, dry_run: bool = False,
) -> dict[str, Any]:
    if phase not in {"prepare", "clean"}:
        raise ValueError("batch phase must be prepare or clean")
    nos3_root = nos3_root.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    if phase == "prepare":
        return _prepare(nos3_root, output_dir, prepare_valid_novatel, dry_run)
    return _clean(nos3_root, output_dir, dry_run)


def _prepare(nos3_root: Path, output_dir: Path, prepare_valid_novatel: bool, dry_run: bool) -> dict[str, Any]:
    preflight = artifact_batch.preflight()
    if not preflight["passed"]:
        raise artifact_batch.ArtifactBatchError(f"SC-ART target overlap detected: {preflight['collisions']}")
    if dry_run:
        return {
            "phase": "prepare", "passed": True, "dry_run": True, "preflight": preflight,
            "order": ["sc_app_prepare", "sc_art_prepare_001_to_005"],
        }

    if _ledger_path(output_dir).exists():
        previous = _read_ledger(output_dir)
        if previous.get("status") in {"preparing", "prepared", "cleaning", "cleanup_incomplete"}:
            raise RuntimeError(f"An active supply-chain batch already exists: {_ledger_path(output_dir)}")

    ledger = _new_ledger("preparing", nos3_root, prepare_valid_novatel)
    _write_ledger(output_dir, ledger)
    app_result = app_batch.prepare(nos3_root=nos3_root, prepare_valid_novatel=prepare_valid_novatel)
    ledger["app"] = app_result
    _write_ledger(output_dir, ledger)
    if not app_result["passed"]:
        ledger.update({"status": "prepare_failed", "failure": "sc_app_prepare_failed"})
        _write_ledger(output_dir, ledger)
        return _result(ledger, output_dir)

    try:
        artifact_result = artifact_batch.prepare(nos3_root=nos3_root, output_dir=output_dir / "artifacts")
    except Exception as error:
        app_cleanup = app_batch.clean(nos3_root=nos3_root)
        ledger.update({
            "status": "prepare_failed_and_compensated",
            "failure": f"{type(error).__name__}: {error}",
            "app_cleanup_after_failure": app_cleanup,
        })
        _write_ledger(output_dir, ledger)
        return _result(ledger, output_dir)

    ledger.update({
        "status": "prepared", "artifact": artifact_result,
        "next_checkpoint": "Run one make config && make fsw && make stop && make launch before batch verification.",
    })
    _write_ledger(output_dir, ledger)
    return _result(ledger, output_dir)


def _clean(nos3_root: Path, output_dir: Path, dry_run: bool) -> dict[str, Any]:
    if dry_run:
        return {
            "phase": "clean", "passed": True, "dry_run": True,
            "order": ["sc_art_rollback_005_to_001", "sc_app_clean"],
        }
    ledger = _read_ledger(output_dir)
    if ledger.get("status") not in {"prepared", "cleanup_incomplete"}:
        raise RuntimeError(f"Batch is not prepared or recoverable: {ledger.get('status')}")
    ledger["status"] = "cleaning"
    _write_ledger(output_dir, ledger)

    applied = ledger.get("artifact", {}).get("applied_profiles", list(artifact_batch.PROFILE_IDS))
    artifact_result = artifact_batch.rollback(
        nos3_root=nos3_root, output_dir=output_dir / "artifacts", profile_ids=reversed(applied),
    )
    ledger["artifact_cleanup"] = artifact_result
    _write_ledger(output_dir, ledger)
    # ART snapshots were taken after APP installation.  Do not uninstall APP
    # until every ART transaction has restored that intermediate state.
    app_result = (
        app_batch.clean(nos3_root=nos3_root)
        if artifact_result["passed"]
        else {"phase": "clean", "passed": False, "skipped": True, "reason": "sc_art_rollback_incomplete"}
    )
    ledger["app_cleanup"] = app_result
    passed = bool(artifact_result["passed"]) and bool(app_result["passed"])
    ledger.update({
        "status": "cleaned" if passed else "cleanup_incomplete",
        "next_checkpoint": "Run one make config && make fsw && make stop && make launch before runtime recovery verification.",
    })
    _write_ledger(output_dir, ledger)
    return _result(ledger, output_dir)


def _new_ledger(status: str, nos3_root: Path, prepare_valid_novatel: bool) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "batch_id": "supply-chain-app-art",
        "status": status,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "nos3_root": str(nos3_root),
        "prepare_valid_novatel": prepare_valid_novatel,
        "artifact_profile_order": list(artifact_batch.PROFILE_IDS),
    }


def _ledger_path(output_dir: Path) -> Path:
    return output_dir / LEDGER_NAME


def _write_ledger(output_dir: Path, ledger: dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = _ledger_path(output_dir)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(ledger, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def _read_ledger(output_dir: Path) -> dict[str, Any]:
    path = _ledger_path(output_dir)
    if not path.is_file():
        raise RuntimeError(f"No supply-chain batch ledger exists: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("batch_id") != "supply-chain-app-art":
        raise RuntimeError(f"Invalid supply-chain batch ledger: {path}")
    return data


def _result(ledger: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    success_states = {"prepared", "cleaned"}
    return {
        "phase": "prepare" if ledger["status"].startswith("prepare") or ledger["status"] == "prepared" else "clean",
        "passed": ledger["status"] in success_states,
        "status": ledger["status"],
        "ledger": str(_ledger_path(output_dir)),
        "details": ledger,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Combined SC-APP + SC-ART prepare/clean orchestration")
    parser.add_argument("--phase", required=True, choices=("prepare", "clean"))
    parser.add_argument("--nos3-root", type=Path, default=Path("/home/leejm/nos3"))
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--prepare-valid-novatel", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    result = run_batch(
        phase=args.phase, nos3_root=args.nos3_root, output_dir=args.output_dir,
        prepare_valid_novatel=args.prepare_valid_novatel, dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
