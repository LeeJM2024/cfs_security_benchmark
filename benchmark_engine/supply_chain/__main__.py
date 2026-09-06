from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmark_engine.supply_chain.matrix import load_matrix
from benchmark_engine.supply_chain.runner import run_profile


def main() -> None:
    parser = argparse.ArgumentParser(description="Supply-chain benchmark matrix and live SC-APP/SC-ART runner")
    parser.add_argument("--profile-id", help="Run one SC-APP or SC-ART profile; omit to list the matrix")
    parser.add_argument("--nos3-root", type=Path, default=Path("/home/leejm/nos3"))
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/supply_chain"))
    parser.add_argument("--operator-container", default="cosmos-openc3-operator-1")
    parser.add_argument("--static-delay-ms", type=int)
    parser.add_argument("--trigger-altitude-m", type=float)
    parser.add_argument("--destination-ip")
    parser.add_argument("--artifact-phase", choices=["prepare", "verify", "rollback", "recover"], default="prepare")
    parser.add_argument("--manifest", type=Path, help="Selected signed SC-ART release manifest")
    parser.add_argument("--trust-anchors", type=Path, help="Local benchmark trust-anchor JSON")
    parser.add_argument("--operator-reload-confirmed", action="store_true", help="Confirm that you manually reloaded CmdTlmServer at the emitted SC-ART checkpoint")
    parser.add_argument("--payload-id", choices=[
        "SC-PAYLOAD-EXFIL", "SC-PAYLOAD-SP001", "SC-PAYLOAD-SP003",
        "SC-PAYLOAD-SP006", "SC-PAYLOAD-SP007", "SC-PAYLOAD-SP008",
    ])
    args = parser.parse_args()

    if not args.profile_id:
        profiles = load_matrix()
        print(f"Supply-chain profiles: {len(profiles)}")
        for profile in profiles:
            suffix = f" payloads={len(profile.payloads)}" if profile.payloads else ""
            print(f"{profile.track}: {profile.profile_id} [{profile.status}]{suffix}")
        return

    options = {
        "operator_container": args.operator_container,
        **{key: value for key, value in {
            "static_delay_ms": args.static_delay_ms,
            "trigger_altitude_m": args.trigger_altitude_m,
            "destination_ip": args.destination_ip,
            "payload_id": args.payload_id,
            "phase": args.artifact_phase,
            "manifest": args.manifest,
            "trust_anchors": args.trust_anchors,
            "operator_reload_confirmed": args.operator_reload_confirmed,
        }.items() if value is not None},
    }
    report = run_profile(
        args.profile_id,
        nos3_root=args.nos3_root,
        output_dir=args.output_dir,
        options=options,
    )
    print(json.dumps(report, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
