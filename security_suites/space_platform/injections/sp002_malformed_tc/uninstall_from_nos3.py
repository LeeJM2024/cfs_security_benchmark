#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


VERIFY_SCRIPT_NAME = "sp002_verify.rb"
SENDER_SCRIPT_NAME = "sp002_send_malformed_tc.py"
DEFAULT_OPERATOR_CONTAINER = "cosmos-openc3-operator-1"
DEFAULT_NOS3_ROOT = Path("/home/leejm/nos3")


def main() -> None:
    args = parse_args()
    nos3_root = resolve_nos3_root(args.nos3_root)

    remove_from_nos3_tree(nos3_root)
    remove_from_operator_container(args.operator_container)

    print("SP002 malformed TC benchmark uninstalled.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Remove SP002 malformed TC benchmark artifacts from a NOS3/OpenC3 tree."
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
        help="OpenC3/COSMOS operator container name used for /tmp cleanup.",
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


def remove_from_nos3_tree(nos3_root: Path) -> None:
    candidates = [
        nos3_root / "gsw/cosmos/config/targets/MISSION/procedures",
        nos3_root / "gsw/cosmos/outputs/tmp/config/targets/MISSION/procedures",
    ]

    for directory in candidates:
        for name in (VERIFY_SCRIPT_NAME, SENDER_SCRIPT_NAME):
            path = directory / name
            if not path.exists():
                print(f"Already absent: {path}")
                continue
            ensure_under(nos3_root, path)
            path.unlink()
            print(f"Removed: {path}")


def remove_from_operator_container(operator_container: str) -> None:
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        print(f"Skipped container cleanup; docker ps failed: {result.stderr.strip()}")
        return

    containers = {line.strip() for line in result.stdout.splitlines()}
    if operator_container not in containers:
        print(f"Skipped container cleanup; {operator_container} is not running.")
        return

    result = subprocess.run(
        [
            "docker",
            "exec",
            operator_container,
            "rm",
            "-f",
            f"/tmp/{VERIFY_SCRIPT_NAME}",
            f"/tmp/{SENDER_SCRIPT_NAME}",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode == 0:
        print(f"Removed container copies from {operator_container}:/tmp")
    else:
        print(f"Skipped container cleanup; docker exec failed: {result.stderr.strip()}")


def ensure_under(root: Path, path: Path) -> None:
    root = root.resolve()
    path = path.resolve()
    if root == path or root not in path.parents:
        raise SystemExit(f"Refusing to remove path outside NOS3 root: {path}")


if __name__ == "__main__":
    main()
