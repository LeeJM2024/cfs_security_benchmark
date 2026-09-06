"""SC-ART release lifecycle runner.

Releases requiring a ground-server reload normally remain operator
checkpointed.  A manifest can explicitly enable the narrow GS002
CmdTlmServer process reload inside the existing COSMOS container.
"""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmark_engine.supply_chain.artifact_transaction import ArtifactTransaction, TransactionError
from benchmark_engine.supply_chain.evidence import SupplyChainEvidence
from benchmark_engine.supply_chain.release_gate import evaluate_release
from benchmark_engine.supply_chain.release_manifest import load_manifest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_ROOT = PROJECT_ROOT / "security_suites" / "supply_chain" / "manifests"
TRUST_ANCHORS = MANIFEST_ROOT / "trust_anchors.json"
DEFAULT_OPERATOR_CONTAINER = "cosmos-openc3-operator-1"


def default_manifest_path(profile_id: str) -> Path:
    names = {
        "SC-ART-001": "poisoned/sc-art-001-sp004.yaml",
        "SC-ART-002": "poisoned/sc-art-002-sp005.yaml",
        "SC-ART-003": "poisoned/sc-art-003-gs002.yaml",
        "SC-ART-004": "poisoned/sc-art-004-gs004.yaml",
        "SC-ART-005": "revoked/sc-art-005-config-rollback-v1.yaml",
    }
    try:
        return MANIFEST_ROOT / names[profile_id]
    except KeyError as error:
        raise ValueError(f"{profile_id} requires --manifest for a selected release variant") from error


def run_artifact_profile(
    profile_id: str, *, nos3_root: Path, output_dir: Path, options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    options = options or {}
    phase = str(options.get("phase", "prepare")).lower()
    if phase not in {"prepare", "verify", "rollback", "recover"}:
        raise ValueError("artifact phase must be prepare, verify, rollback, or recover")
    manifest_path = Path(options.get("manifest") or default_manifest_path(profile_id)).expanduser().resolve()
    manifest = load_manifest(manifest_path)
    if manifest["profile_id"] != profile_id and profile_id != "SC-ART-005":
        raise ValueError(f"Manifest {manifest_path} belongs to {manifest['profile_id']}, not {profile_id}")

    if profile_id == "SC-ART-005":
        return _run_native_release_attack(
            manifest, manifest_path=manifest_path, nos3_root=nos3_root, output_dir=output_dir,
            phase=phase, options=options,
        )

    run_id = f"{profile_id.lower()}-{manifest['release_id']}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    state_root = output_dir / "transactions"
    decision = evaluate_release(
        manifest,
        repo_root=PROJECT_ROOT,
        trust_anchor_path=Path(options.get("trust_anchors") or TRUST_ANCHORS),
        platform_versions=dict(options.get("platform_versions", {})),
        minimum_versions=dict(options.get("minimum_versions", {})),
    )
    transaction = ArtifactTransaction(manifest, PROJECT_ROOT, nos3_root, state_root)
    lifecycle = dict(manifest["lifecycle"])
    details: dict[str, Any] = {
        "track": "artifact", "phase": phase, "manifest": str(manifest_path),
        "release_id": manifest["release_id"], "release_version": manifest["version"],
        "release_status": manifest["status"], "manifest_digest": decision.manifest_digest,
        "content_digests": decision.content_digests, "gate_reasons": list(decision.reasons),
        "lifecycle": lifecycle,
    }
    attack_succeeded = False
    recovery = False
    control_passed = False

    if phase == "prepare":
        if not decision.accepted:
            control_passed = True
            details["deployment"] = "rejected_before_apply"
        else:
            ledger = transaction.apply()
            details["transaction"] = ledger
            details["deployment"] = "applied"
            details["checkpoint"] = _checkpoint(lifecycle, "post_apply")
    elif phase == "verify":
        if not decision.accepted:
            control_passed = True
            details["verification"] = "not_run_release_rejected"
        elif lifecycle.get("requires_operator_reload") and not bool(options.get("operator_reload_confirmed")) and not bool(options.get("auto_cmdtlmserver", lifecycle.get("auto_cmdtlmserver", profile_id == "SC-ART-003"))):
            details["checkpoint"] = _checkpoint(lifecycle, "before_verify")
            details["verification"] = "blocked_waiting_for_operator_reload_confirmation"
        else:
            verification = _verify_existing_adapter(manifest, nos3_root, output_dir, options)
            details["verification"] = verification
            attack_succeeded = bool(verification.get("passed", False))
    elif phase == "rollback":
        rollback = transaction.rollback()
        details["rollback"] = rollback
        recovery = bool(rollback["restored"])
        details["checkpoint"] = _checkpoint(lifecycle, "post_rollback")
    elif lifecycle.get("requires_operator_reload") and not bool(options.get("operator_reload_confirmed")) and not bool(options.get("auto_cmdtlmserver", lifecycle.get("auto_cmdtlmserver", profile_id == "SC-ART-003"))):
        details["checkpoint"] = _checkpoint(lifecycle, "before_recovery")
        details["recovery"] = "blocked_waiting_for_operator_reload_confirmation"
    else:
        recovery_result = _recover_existing_adapter(manifest, output_dir, options)
        details["recovery"] = recovery_result
        recovery = bool(recovery_result.get("passed", False))

    evidence = SupplyChainEvidence(
        profile_id=profile_id,
        passed=attack_succeeded,  # PASS is always attack success, never a defended rejection.
        artifact_accepted=decision.accepted,
        payload_invoked=attack_succeeded,
        mission_effect_observed=attack_succeeded,
        recovery_observed=recovery,
        details={**details, "attack_succeeded": attack_succeeded, "control_passed": control_passed},
    ).to_dict()
    evidence.update({
        "run_id": run_id, "generated_at": datetime.now(timezone.utc).isoformat(),
        "attack_succeeded": attack_succeeded, "control_passed": control_passed,
    })
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f"{profile_id.lower()}-{manifest['release_id']}-{phase}.json"
    report_path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return evidence


def _run_native_release_attack(
    manifest: dict[str, Any], *, manifest_path: Path, nos3_root: Path, output_dir: Path,
    phase: str, options: dict[str, Any],
) -> dict[str, Any]:
    """Exercise an actual outdated/revoked release without invoking our gate.

    This deliberately uses the same transaction/build/runtime path as the
    other SC-ART cases.  PASS means the baseline NOS3 release ingress accepted
    a release which an external provenance gate should have rejected.
    """
    lifecycle = dict(manifest["lifecycle"])
    if lifecycle.get("adapter") == "acceptance_only":
        raise ValueError("SC-ART-005 needs a concrete release fixture with a real target adapter")
    transaction = ArtifactTransaction(manifest, PROJECT_ROOT, nos3_root, output_dir / "transactions")
    attack_succeeded = False
    recovery = False
    recommendation = (
        "RECOMMENDATION: integrate the benchmark SC release gate into the NOS3 release/deploy ingress "
        "to enforce signed manifest, revocation, compatibility, and anti-rollback policy before artifact copy/build."
    )
    run_id = f"sc-art-005-{manifest['release_id']}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    details = {
        "track": "artifact", "phase": phase, "test_mode": "native_nos3_release_attack_without_benchmark_gate",
        "manifest": str(manifest_path), "release_id": manifest["release_id"],
        "release_version": manifest["version"], "release_status": manifest["status"],
        "benchmark_gate_invoked": False,
        "recommendation": recommendation,
    }
    if phase == "prepare":
        details["transaction"] = transaction.apply()
        details["deployment"] = "accepted_by_unprotected_nos3_release_path"
        details["checkpoint"] = _checkpoint(lifecycle, "post_apply")
    elif phase == "verify":
        verification = _verify_existing_adapter(manifest, nos3_root, output_dir, options)
        details["verification"] = verification
        attack_succeeded = bool(verification.get("passed", False))
        if attack_succeeded:
            print(f"SC-ART-005 {recommendation}")
    elif phase == "rollback":
        rollback = transaction.rollback()
        details["rollback"] = rollback
        recovery = bool(rollback["restored"])
        details["checkpoint"] = _checkpoint(lifecycle, "post_rollback")
    elif phase == "recover":
        recovery_result = _recover_existing_adapter(manifest, output_dir, options)
        details["recovery"] = recovery_result
        recovery = bool(recovery_result.get("passed", False))
    else:
        raise ValueError(f"Unsupported SC-ART-005 phase: {phase}")
    details.update({"attack_succeeded": attack_succeeded, "control_passed": False})
    evidence = SupplyChainEvidence(
        profile_id="SC-ART-005", passed=attack_succeeded,
        artifact_accepted=True, payload_invoked=attack_succeeded,
        mission_effect_observed=attack_succeeded, recovery_observed=recovery,
        details=details,
    ).to_dict()
    evidence.update({
        "run_id": run_id, "generated_at": datetime.now(timezone.utc).isoformat(),
        "attack_succeeded": attack_succeeded, "control_passed": False,
    })
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f"sc-art-005-{manifest['release_id']}-{phase}.json"
    report_path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return evidence


def _checkpoint(lifecycle: dict[str, Any], phase: str) -> dict[str, Any]:
    actions: list[str] = []
    if lifecycle.get("requires_build_relaunch"):
        actions.append("Operator runs the declared NOS3 build/relaunch workflow; runner will not start services.")
    if lifecycle.get("requires_operator_reload"):
        if lifecycle.get("auto_cmdtlmserver"):
            actions.append("Runner restarts CmdTlmServer in the existing COSMOS container before verify/recovery.")
        else:
            actions.append("Operator manually reloads CmdTlmServer, then reruns verify with operator_reload_confirmed=true.")
    return {"phase": phase, "required": bool(actions), "operator_actions": actions}


def _verify_existing_adapter(manifest: dict[str, Any], nos3_root: Path, output_dir: Path, options: dict[str, Any]) -> dict[str, Any]:
    """Invoke existing SP verifiers only; GS adapters intentionally remain checkpointed.

    GS002/GS004 use staged observation helpers that reuse their scenario,
    COSMOS encoding, telemetry, and recovery logic but never call a service
    restart helper.
    """
    adapter = str(manifest["lifecycle"]["adapter"])
    container = str(options.get("operator_container", DEFAULT_OPERATOR_CONTAINER))
    if adapter in {"gs002", "gs004"}:
        from benchmark_engine.supply_chain.ground_staged_verify import verify
        return verify(
            adapter,
            manifest,
            container=container,
            output_dir=output_dir,
            auto_restart=bool(options.get("auto_cmdtlmserver", manifest["lifecycle"].get("auto_cmdtlmserver", manifest.get("profile_id") == "SC-ART-003"))),
        )
    if adapter == "sp004":
        script = nos3_root / "gsw/cosmos/config/targets/MISSION/procedures/sp004_verify.rb"
        report_dir = str(options.get("sp004_report_dir", f"/tmp/sc_art_sp004/{manifest['release_id']}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"))
        env = ["-e", f"SP004_REPORT_DIR={report_dir}"]
        selected_profile = str(manifest["lifecycle"].get("sp004_only", "")).strip()
        if selected_profile:
            env.extend(["-e", f"SP004_ONLY={selected_profile}"])
    elif adapter == "sp005":
        script = nos3_root / "gsw/cosmos/config/targets/MISSION/procedures/sp005_verify.rb"
        profile = str(manifest["lifecycle"].get("sp005_profile", ""))
        report_dir = str(options.get("sp005_report_dir", f"/tmp/sc_art_sp005/{manifest['release_id']}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"))
        env = ["-e", f"SP005_REPORT_DIR={report_dir}"]
        if profile:
            env.extend(["-e", f"SP005_PROFILE={profile}"])
    elif adapter == "component_variant":
        script = nos3_root / "gsw/cosmos/config/targets/MISSION/procedures/sc_art005_generic_adcs_variant_verify.rb"
        report_dir = str(options.get("component_variant_report_dir", f"/tmp/sc_art005_component_variant/{manifest['release_id']}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"))
        env = ["-e", f"SC_ART005_REPORT_DIR={report_dir}"]
        profile = str(manifest["lifecycle"].get("component_release", "generic_adcs"))
    else:
        raise ValueError(f"Unsupported artifact adapter: {adapter}")
    if not script.is_file():
        return {"passed": False, "error": f"Installed verifier is absent: {script}"}
    command = ["docker", "exec", *env, container, "/usr/bin/ruby", str(script)]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if adapter == "sp004":
        summary = _read_container_json(container, f"{report_dir}/summary.json")
        return {
            "passed": str(summary.get("result", "")).upper() == "PASS",
            "returncode": completed.returncode,
            "stderr": completed.stderr.strip(),
            "verifier_report_dir": report_dir,
            "selected_profile": selected_profile or None,
            "source_verifier_summary": summary,
            "stdout": completed.stdout.strip(),
        }
    if adapter == "sp005":
        summary = _read_container_json(container, f"{report_dir}/summary.json")
        return {
            "passed": str(summary.get("result", "")).upper() == "PASS",
            "returncode": completed.returncode,
            "stderr": completed.stderr.strip(),
            "verifier_report_dir": report_dir,
            "selected_profile": profile or None,
            "source_verifier_summary": summary,
            "stdout": completed.stdout.strip(),
        }
    if adapter == "component_variant":
        summary = _read_container_json(container, f"{report_dir}/summary.json")
        return {
            "passed": str(summary.get("result", "")).upper() == "PASS",
            "returncode": completed.returncode,
            "stderr": completed.stderr.strip(),
            "verifier_report_dir": report_dir,
            "selected_component_release": profile,
            "source_verifier_summary": summary,
            "stdout": completed.stdout.strip(),
        }
    parsed = _parse_json(completed.stdout)
    return {"passed": bool(parsed.get("passed", False)), "returncode": completed.returncode, "stderr": completed.stderr.strip(), "verifier": parsed}


def _recover_existing_adapter(manifest: dict[str, Any], output_dir: Path, options: dict[str, Any]) -> dict[str, Any]:
    adapter = str(manifest["lifecycle"]["adapter"])
    if adapter not in {"gs002", "gs004"}:
        return {"passed": True, "reason": "filesystem rollback is the declared recovery for this adapter"}
    from benchmark_engine.supply_chain.ground_staged_verify import recover
    return recover(
        adapter,
        manifest,
        container=str(options.get("operator_container", DEFAULT_OPERATOR_CONTAINER)),
        output_dir=output_dir,
        auto_restart=bool(options.get("auto_cmdtlmserver", manifest["lifecycle"].get("auto_cmdtlmserver", manifest.get("profile_id") == "SC-ART-003"))),
    )


def _parse_json(stdout: str) -> dict[str, Any]:
    start, end = stdout.find("{"), stdout.rfind("}")
    if start >= 0 and end > start:
        try:
            parsed = json.loads(stdout[start:end + 1])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    return {"error": "Verifier did not emit a JSON object", "stdout": stdout.strip()}


def _read_container_json(container: str, path: str) -> dict[str, Any]:
    result = subprocess.run(
        ["docker", "exec", container, "cat", path], text=True, capture_output=True, check=False
    )
    if result.returncode != 0:
        return {"error": "Unable to read verifier summary", "path": path, "stderr": result.stderr.strip()}
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        return {"error": f"Invalid verifier summary JSON: {error}", "path": path, "stdout": result.stdout.strip()}
    return parsed if isinstance(parsed, dict) else {"error": "Verifier summary was not an object", "path": path}
