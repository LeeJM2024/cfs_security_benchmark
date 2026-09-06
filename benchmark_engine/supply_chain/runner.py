from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmark_engine.supply_chain.evidence import SupplyChainEvidence
from benchmark_engine.supply_chain.artifact_runner import run_artifact_profile
from benchmark_engine.supply_chain.matrix import SupplyChainProfile, load_matrix


DEFAULT_OPERATOR_CONTAINER = "cosmos-openc3-operator-1"
VERIFIER_RELATIVE_PATH = Path("gsw/cosmos/config/targets/MISSION/procedures/sc_vendor_verify.rb")


def run_profile(
    profile_id: str,
    *,
    nos3_root: Path,
    output_dir: Path,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one installed SC-APP profile through the live COSMOS verifier.

    The caller is responsible for the normal NOS3 setup lifecycle (install,
    build, and launch). This runner deliberately executes only an already
    declared scenario and writes its normalized evidence envelope.
    """
    base_profile_id, embedded_payload = _split_profile_id(profile_id)
    profile = _find_profile(base_profile_id)
    if profile.track == "artifact":
        if embedded_payload:
            raise ValueError("Artifact profiles do not use an embedded app payload id")
        return run_artifact_profile(profile.profile_id, nos3_root=nos3_root, output_dir=output_dir, options=options)
    if profile.track != "app":
        raise ValueError(f"Unsupported supply-chain track: {profile.track}")

    opts = options or {}
    metadata = profile.metadata or {}
    trigger_mode, coordination_mode = _profile_modes(metadata)
    container = str(opts.get("operator_container", DEFAULT_OPERATOR_CONTAINER))
    verifier = nos3_root.expanduser().resolve() / VERIFIER_RELATIVE_PATH
    if not verifier.is_file():
        raise FileNotFoundError(f"Supply-chain verifier is not installed: {verifier}")

    run_id = f"{profile_id.lower()}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    verifier_report_dir = str(opts.get("verifier_report_dir", f"/tmp/sc_vendor_results/{run_id}"))
    payload_id = str(opts.get("payload_id", embedded_payload or "SC-PAYLOAD-EXFIL"))
    if payload_id not in profile.payloads:
        raise ValueError(f"Payload {payload_id} is not declared for {profile.profile_id}")
    env = {
        "SC_REPORT_DIR": verifier_report_dir,
        "SC_TRIGGER_MODE": trigger_mode,
        "SC_COORDINATION_MODE": str(coordination_mode),
        "SC_PAYLOAD_ID": payload_id,
    }
    for option_key, env_key in (
        ("static_delay_ms", "SC_STATIC_DELAY_MS"),
        ("trigger_altitude_m", "SC_TRIGGER_ALTITUDE_M"),
        ("destination_ip", "SC_DESTINATION_IP"),
    ):
        if option_key in opts:
            env[env_key] = str(opts[option_key])

    command = ["docker", "exec"]
    for key, value in env.items():
        command.extend(("-e", f"{key}={value}"))
    command.extend((container, "/usr/bin/ruby", str(verifier)))
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    verifier_result = _parse_verifier_output(completed.stdout)

    evidence = SupplyChainEvidence(
        profile_id=profile_id,
        passed=bool(verifier_result.get("passed", False)),
        artifact_accepted=bool(verifier_result.get("artifact_accepted", False)),
        benign_contract_passed=bool(verifier_result.get("benign_contract_passed", False)),
        dormancy_observed=bool(verifier_result.get("dormancy_observed", False)),
        trigger_observed=bool(verifier_result.get("trigger_observed", False)),
        coordination_observed=bool(verifier_result.get("coordination_observed", False)),
        payload_invoked=bool(verifier_result.get("payload_invoked", False)),
        mission_effect_observed=bool(verifier_result.get("mission_effect_observed", False)),
        recovery_observed=bool(verifier_result.get("recovery_observed", False)),
        details={
            "scenario": metadata,
            "container": container,
            "verifier_report_dir": verifier_report_dir,
            "returncode": completed.returncode,
            "stderr": completed.stderr.strip(),
            "verifier": verifier_result,
        },
    )
    report = evidence.to_dict()
    report["run_id"] = run_id
    report["generated_at"] = datetime.now(timezone.utc).isoformat()

    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f"{profile.profile_id.lower()}.json"
    report_path.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return report


def _find_profile(profile_id: str) -> SupplyChainProfile:
    for profile in load_matrix():
        if profile.profile_id == profile_id:
            return profile
    raise KeyError(f"Unknown supply-chain profile: {profile_id}")


def _split_profile_id(profile_id: str) -> tuple[str, str | None]:
    """Accept SC-APP-001__SC-PAYLOAD-SP001 as a concrete 30-case id."""
    for separator in ("__", ":"):
        if separator in profile_id:
            base, payload = profile_id.split(separator, 1)
            return base, payload
    return profile_id, None


def _profile_modes(metadata: dict[str, Any]) -> tuple[str, int]:
    trigger = str(metadata.get("trigger", ""))
    coordination = str(metadata.get("coordination", ""))
    trigger_modes = {"static": "static", "dynamic_novatel": "dynamic"}
    coordination_modes = {"none": 0, "software_bus": 1, "posix_fifo": 2}
    if trigger not in trigger_modes or coordination not in coordination_modes:
        raise ValueError(f"Unsupported app scenario metadata: {metadata}")
    return trigger_modes[trigger], coordination_modes[coordination]


def _parse_verifier_output(stdout: str) -> dict[str, Any]:
    start = stdout.find("{")
    end = stdout.rfind("}")
    if start >= 0 and end > start:
        try:
            parsed = json.loads(stdout[start : end + 1])
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            return parsed
    return {
        "passed": False,
        "error": {
            "class": "VerifierOutputError",
            "message": "Verifier did not emit a JSON result",
            "stdout": stdout.strip(),
        },
    }
