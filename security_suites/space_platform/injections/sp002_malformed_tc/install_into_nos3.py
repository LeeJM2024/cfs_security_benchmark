#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


VERIFY_SCRIPT_NAME = "sp002_verify.rb"
SENDER_SCRIPT_NAME = "sp002_send_malformed_tc.py"
RUNNER_SCRIPT_NAME = "sp002_run_live.py"
DEFAULT_OPERATOR_CONTAINER = "cosmos-openc3-operator-1"
DEFAULT_NOS3_ROOT = Path("/home/leejm/nos3")


def main() -> None:
    args = parse_args()
    nos3_root = resolve_nos3_root(args.nos3_root)
    integration_root = Path(__file__).resolve().parent

    if not (integration_root / SENDER_SCRIPT_NAME).exists():
        raise SystemExit(f"Missing SP002 sender: {integration_root / SENDER_SCRIPT_NAME}")
    if not (integration_root / VERIFY_SCRIPT_NAME).exists():
        raise SystemExit(f"Missing SP002 verifier: {integration_root / VERIFY_SCRIPT_NAME}")
    if not (integration_root / RUNNER_SCRIPT_NAME).exists():
        raise SystemExit(f"Missing SP002 live runner: {integration_root / RUNNER_SCRIPT_NAME}")

    install_to_nos3_tree(integration_root, nos3_root)
    copy_to_operator_container(integration_root, args.operator_container)

    print("SP002 malformed TC benchmark installed.")
    print("")
    print("Benchmark workflow:")
    print("  1. prepare/install: copy SP002 sender and COSMOS/OpenC3 verifier")
    print("  2. build:           no FSW build required for SP002")
    print("  3. run/verify:      launch NOS3, then run the installed verifier")
    print("  4. uninstall:       run uninstall_from_nos3.py after benchmark testing is complete")
    print("")
    print("Verifier command after launch:")
    print("  ./sp002_run_live.py --mode safe")
    print("")
    print("Mode examples:")
    print("  ./sp002_run_live.py --mode safe")
    print("  ./sp002_run_live.py --mode hazardous --confirm-hazard")
    print("  ./sp002_run_live.py --mode short-all --confirm-hazard")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install SP002 malformed TC benchmark artifacts into a NOS3/OpenC3 tree."
    )
    parser.add_argument(
        "--nos3-root",
        type=Path,
        default=None,
        help="NOS3 repository root. Defaults to cwd when it is NOS3, otherwise /home/leejm/nos3.",
    )
    parser.add_argument(
        "--operator-container",
        default=DEFAULT_OPERATOR_CONTAINER,
        help="OpenC3/COSMOS operator container name used for /tmp verifier/sender copy.",
    )
    return parser.parse_args()


def resolve_nos3_root(arg: Path | None) -> Path:
    candidates = []
    if arg is not None:
        candidates.append(arg)
    candidates.append(Path.cwd())
    candidates.append(DEFAULT_NOS3_ROOT)

    for candidate in candidates:
        root = candidate.expanduser().resolve()
        if (root / "cfg/nos3_defs/targets.cmake").exists() and (root / "gsw/cosmos").exists():
            return root

    raise SystemExit("Could not locate NOS3 root. Pass --nos3-root /path/to/nos3.")


def install_to_nos3_tree(integration_root: Path, nos3_root: Path) -> None:
    procedures = [
        nos3_root / "gsw/cosmos/config/targets/MISSION/procedures",
    ]

    generated = nos3_root / "gsw/cosmos/outputs/tmp/config/targets/MISSION/procedures"
    if generated.exists():
        procedures.append(generated)

    for directory in procedures:
        directory.mkdir(parents=True, exist_ok=True)
        for name in (VERIFY_SCRIPT_NAME, SENDER_SCRIPT_NAME):
            destination = directory / name
            shutil.copy2(integration_root / name, destination)
            if name.endswith(".py"):
                destination.chmod(destination.stat().st_mode | 0o111)
            print(f"Installed: {destination}")


def copy_to_operator_container(integration_root: Path, operator_container: str) -> None:
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        print(f"Skipped container copy; docker ps failed: {result.stderr.strip()}")
        return

    containers = {line.strip() for line in result.stdout.splitlines()}
    if operator_container not in containers:
        print(f"Skipped container copy; {operator_container} is not running.")
        return

    for name in (VERIFY_SCRIPT_NAME, SENDER_SCRIPT_NAME):
        result = subprocess.run(
            ["docker", "cp", str(integration_root / name), f"{operator_container}:/tmp/{name}"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode == 0:
            print(f"Copied into {operator_container}:/tmp/{name}")
        else:
            print(f"Skipped {name} container copy; docker cp failed: {result.stderr.strip()}")

    subprocess.run(
        ["docker", "exec", operator_container, "chmod", "+x", f"/tmp/{SENDER_SCRIPT_NAME}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


if __name__ == "__main__":
    main()
