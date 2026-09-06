from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from benchmark_engine.lifecycle.registry import SpaceInjection, space_injections


def sp005_preflight(injection: SpaceInjection, nos3_root: Path) -> tuple[bool, str]:
    """Confirm that all SP005 source-level profiles were applied before runtime verification.

    SP005 is intentionally unlike the other space scenarios: its attack payloads
    modify NOS3 source/simulator configuration and only become runtime-visible
    after the normal NOS3 rebuild and restart.  Running its Ruby scorer against
    an unprepared checkout produces false FAIL results rather than an attack
    measurement, so this is a hard batch checkpoint.
    """
    manifest_path = injection.root / "sp005_profiles.json"
    state_path = nos3_root / ".sp005_component_config_pollution" / "state.json"
    if not manifest_path.is_file():
        return False, f"missing SP005 manifest: {manifest_path}"
    if not state_path.is_file():
        return False, f"missing SP005 applied-profile state: {state_path}"

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return False, f"cannot read SP005 preparation state: {error}"

    expected = {profile["id"] for profile in manifest}
    active = set(state.get("active_profiles") or [])
    missing = sorted(expected - active)
    if missing:
        return False, f"SP005 profiles not applied: {', '.join(missing)}"
    return True, "all SP005 profiles are applied; verify after the required rebuild/restart"


def sp005_active_profiles(nos3_root: Path) -> tuple[list[str], str]:
    """Report the source-level SP005 state without treating an absent state file as an error."""
    state_path = nos3_root / ".sp005_component_config_pollution" / "state.json"
    if not state_path.is_file():
        return [], "no SP005 state file"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot read SP005 state: {error}") from error
    return list(state.get("active_profiles") or []), str(state_path)


def prepare_sp005(injection: SpaceInjection, nos3_root: Path) -> int:
    apply_script = injection.root / "apply_profile.py"
    command = [sys.executable, str(apply_script), "--nos3-root", str(nos3_root), "--all"]
    print(f"SP005: prepare {' '.join(command)}")
    result = subprocess.run(command, check=False)
    if result.returncode:
        return result.returncode

    print("SP005 checkpoint complete: profiles applied.")
    print(f"Next run in {nos3_root}: make config && make fsw && make sim")
    print("Then restart NOS3/cFS/sims and run: python3 -m benchmark_engine.space_platform.verify_all --phase sp005")
    return 0


def restore_sp005(injection: SpaceInjection, nos3_root: Path) -> int:
    apply_script = injection.root / "apply_profile.py"
    command = [sys.executable, str(apply_script), "--nos3-root", str(nos3_root), "--restore"]
    print(f"SP005: restore {' '.join(command)}")
    result = subprocess.run(command, check=False)
    if result.returncode:
        return result.returncode
    print("SP005 restore checkpoint complete.")
    print(f"Next run in {nos3_root}: make config && make fsw && make sim, then restart NOS3/cFS/sims.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Run clean-baseline or SP005-only Space-platform verification in COSMOS")
    parser.add_argument("--cosmos-container", default="cosmos-openc3-operator-1")
    parser.add_argument("--nos3-root", type=Path, default=Path("/home/leejm/nos3"))
    parser.add_argument("--sp001-risk", choices=("safe", "hazardous", "all"), default="safe")
    parser.add_argument("--confirm-hazard", action="store_true", help="Allow explicitly selected hazardous verifier profiles")
    sp005_action = parser.add_mutually_exclusive_group()
    sp005_action.add_argument(
        "--prepare-sp005",
        action="store_true",
        help="apply all source-level SP005 profiles, then stop at the required NOS3 rebuild/restart checkpoint",
    )
    sp005_action.add_argument(
        "--restore-sp005",
        action="store_true",
        help="restore SP005 source/simulator configuration backups, then stop at the required NOS3 rebuild/restart checkpoint",
    )
    parser.add_argument(
        "--phase",
        choices=("clean", "sp005"),
        default="clean",
        help="clean runs SP001-SP004 and SP006-SP008 only; sp005 runs SP005 only (default: clean)",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.sp001_risk != "safe" and not args.confirm_hazard:
        raise SystemExit("SP001 hazardous profiles require --confirm-hazard")

    injections = space_injections()
    sp005 = next(injection for injection in injections if injection.case_id == "SP005")
    if args.prepare_sp005:
        raise SystemExit(prepare_sp005(sp005, args.nos3_root))
    if args.restore_sp005:
        raise SystemExit(restore_sp005(sp005, args.nos3_root))

    if args.phase == "sp005":
        sp005_ready, sp005_message = sp005_preflight(sp005, args.nos3_root)
        if not sp005_ready:
            raise SystemExit(
                "SP005 batch checkpoint is not ready: " + sp005_message + "\n"
                "Run: python3 -m benchmark_engine.space_platform.verify_all --prepare-sp005\n"
                f"Then in {args.nos3_root}: make config && make fsw && make sim; restart NOS3/cFS/sims; rerun with --phase sp005."
            )
        selected_injections = [sp005]
        print(f"SP005 phase preflight: PASS ({sp005_message})")
    else:
        active_profiles, state_location = sp005_active_profiles(args.nos3_root)
        if active_profiles:
            raise SystemExit(
                "Clean phase refuses to run while SP005 source/simulator pollution is active: "
                f"{', '.join(active_profiles)} ({state_location}).\n"
                "Run: python3 -m benchmark_engine.space_platform.verify_all --restore-sp005\n"
                "Then rebuild/restart NOS3 before rerunning --phase clean."
            )
        selected_injections = [injection for injection in injections if injection.case_id != "SP005"]
        print("Clean phase preflight: PASS (SP005 source/simulator pollution is inactive)")

    failures: list[str] = []
    copied = []
    for injection in selected_injections:
        if injection.case_id == "SP002":
            runner = injection.root / "sp002_run_live.py"
            if not runner.is_file():
                print(f"SP002: missing dedicated runtime runner: {runner}")
                failures.append(injection.case_id)
            else:
                # SP002's Ruby verifier invokes a Python raw-packet sender.
                # Its dedicated runner copies both files into COSMOS and sets
                # the dynamically discovered TO_LAB return address.
                copied.append((injection, runner))
            continue

        remote_script = f"/tmp/{injection.case_id.lower()}_verify.rb"
        copy_command = ["docker", "cp", str(injection.verify_script), f"{args.cosmos_container}:{remote_script}"]
        print(f"{injection.case_id}: copy {' '.join(copy_command)}")
        if args.dry_run or subprocess.run(copy_command, check=False).returncode == 0:
            copied.append((injection, remote_script))
        else:
            failures.append(injection.case_id)

    for injection, remote_script in copied:
        if injection.case_id == "SP002":
            execute_command = [
                sys.executable,
                str(remote_script),
                "--mode",
                "safe",
                "--operator-container",
                args.cosmos_container,
            ]
            if args.dry_run:
                execute_command.append("--print-only")
            print(f"SP002: verify {' '.join(execute_command)}")
            if not args.dry_run and subprocess.run(execute_command, check=False).returncode:
                failures.append(injection.case_id)
            continue

        environment: dict[str, str] = {}
        if injection.case_id == "SP001":
            environment["SP001_RISK"] = args.sp001_risk
            # In affected NOS3/OpenC3 runs the decoded RW HK cache can remain
            # stale after a restart although the real UART command and reply
            # are present.  Run this one profile with its dedicated live-link
            # verifier below; retain the original Ruby verifier for every
            # other SP001 profile.
            if args.sp001_risk != "hazardous":
                environment["SP001_EXCLUDE_PROFILES"] = "rw_set_torque"
            if args.confirm_hazard:
                environment["SP001_CONFIRM_HAZARD"] = "YES"
        execute_command = ["docker", "exec"]
        for key, value in environment.items():
            execute_command.extend(["-e", f"{key}={value}"])
        execute_command.extend([args.cosmos_container, "/usr/bin/ruby", remote_script])

        print(f"{injection.case_id}: verify {' '.join(execute_command)}")
        if args.dry_run:
            if injection.case_id == "SP001" and args.sp001_risk != "hazardous":
                runner = injection.root / "sp001_rw_set_torque_live.py"
                live_command = [sys.executable, str(runner), "--operator-container", args.cosmos_container]
                print(f"SP001 rw_set_torque: verify {' '.join(live_command)}")
            continue
        if subprocess.run(execute_command, check=False).returncode:
            failures.append(injection.case_id)
            continue

        if injection.case_id == "SP001" and args.sp001_risk != "hazardous":
            runner = injection.root / "sp001_rw_set_torque_live.py"
            live_command = [sys.executable, str(runner), "--operator-container", args.cosmos_container]
            print(f"SP001 rw_set_torque: verify {' '.join(live_command)}")
            if subprocess.run(live_command, check=False).returncode:
                failures.append(injection.case_id)

    if failures:
        raise SystemExit(f"Space verification phase {args.phase} failed: {', '.join(failures)}")
    print(f"Space verification phase {args.phase} complete")


if __name__ == "__main__":
    main()
