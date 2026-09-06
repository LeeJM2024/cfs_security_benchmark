#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


COMPONENT_PATH = "sp001_sb_spoof/fsw/cfs"
APP_ENTRY = f"        {COMPONENT_PATH}\n"
COMPONENT_NAME = "sp001_sb_spoof"
COSMOS_DICT_NAME = "SP001_SB_SPOOF.txt"
VERIFY_SCRIPT_NAME = "sp001_verify.rb"
DEFAULT_OPERATOR_CONTAINER = "cosmos-openc3-operator-1"
BENCHMARK_MARKERS = [
    "SP-001 Software Bus spoof benchmark command interface",
    "SP001 malicious app",
]


def main() -> None:
    args = parse_args()
    nos3_root = args.nos3_root.resolve()

    if not (nos3_root / "cfg/nos3_defs/targets.cmake").exists():
        raise SystemExit(f"{nos3_root} does not look like a NOS3 repository root.")

    remove_targets_entry(nos3_root / "cfg/nos3_defs/targets.cmake")
    remove_startup_entry(nos3_root / "cfg/nos3_defs/cpu1_cfe_es_startup.scr")

    build_targets = nos3_root / "cfg/build/nos3_defs/targets.cmake"
    if build_targets.exists():
        remove_targets_entry(build_targets)
    build_startup = nos3_root / "cfg/build/nos3_defs/cpu1_cfe_es_startup.scr"
    if build_startup.exists():
        remove_startup_entry(build_startup)
    runtime_startup = nos3_root / "fsw/build/exe/cpu1/cf/cfe_es_startup.scr"
    if runtime_startup.exists():
        remove_startup_entry(runtime_startup)

    remove_component(nos3_root)
    remove_cosmos_dictionary(nos3_root)
    remove_verifier(nos3_root)
    remove_container_verifier(args.operator_container)
    remove_build_and_runtime_artifacts(nos3_root)

    print("SP001 SB spoof integration uninstalled.")
    print("")
    print("Next: run `make config` before the next normal NOS3 build/launch.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Remove SP001 Software Bus spoof benchmark artifacts from a NOS3 source tree."
    )
    parser.add_argument(
        "--nos3-root",
        type=Path,
        default=Path.cwd(),
        help="NOS3 repository root. Defaults to the current working directory.",
    )
    parser.add_argument(
        "--operator-container",
        default=DEFAULT_OPERATOR_CONTAINER,
        help="OpenC3/COSMOS operator container name used for optional /tmp verifier cleanup.",
    )
    return parser.parse_args()


def remove_targets_entry(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    updated = remove_targets_component(text)

    if updated == text:
        print(f"targets.cmake did not contain {COMPONENT_NAME}: {path}")
        return

    path.write_text(updated, encoding="utf-8")
    print(f"Removed {COMPONENT_NAME} from targets.cmake: {path}")


def remove_targets_component(text: str) -> str:
    updated_lines = []

    for line in text.splitlines(keepends=True):
        if COMPONENT_PATH not in line:
            updated_lines.append(line)
            continue

        newline = "\n" if line.endswith("\n") else ""
        body = line[:-1] if newline else line
        prefix = body.replace(COMPONENT_PATH, "").rstrip()
        if prefix:
            updated_lines.append(prefix + newline)

    return "".join(updated_lines)


def remove_startup_entry(path: Path) -> None:
    """Remove only SP001's resident-app record, preserving other benchmarks."""
    if not path.exists():
        print(f"cFE startup script already absent: {path}")
        return

    text = path.read_text(encoding="utf-8")
    updated = "".join(
        line
        for line in text.splitlines(keepends=True)
        if "sp001_sb_spoof" not in line and "SP001_AppMain" not in line and "SP001_SPOOFER" not in line
    )
    if updated == text:
        print(f"cFE startup script did not contain {COMPONENT_NAME}: {path}")
        return

    path.write_text(updated, encoding="utf-8")
    print(f"Removed {COMPONENT_NAME} from cFE startup script: {path}")


def remove_component(nos3_root: Path) -> None:
    remove_path(nos3_root, nos3_root / "components" / COMPONENT_NAME)


def remove_cosmos_dictionary(nos3_root: Path) -> None:
    candidates = [
        nos3_root / "gsw/cosmos/config/targets/CFS/cmd_tlm" / COSMOS_DICT_NAME,
        nos3_root / "gsw/cosmos/outputs/tmp/config/targets/CFS/cmd_tlm" / COSMOS_DICT_NAME,
    ]

    for path in candidates:
        if not path.exists():
            print(f"COSMOS/OpenC3 dictionary already absent: {path}")
            continue

        backup = path.with_suffix(path.suffix + ".sp001.bak")
        text = path.read_text(encoding="utf-8", errors="ignore")

        if backup.exists():
            ensure_under(nos3_root, backup)
            shutil.copy2(backup, path)
            backup.unlink()
            print(f"Restored previous COSMOS/OpenC3 dictionary backup: {path}")
        elif any(marker in text for marker in BENCHMARK_MARKERS):
            remove_path(nos3_root, path)
        else:
            print(f"Left non-benchmark COSMOS/OpenC3 dictionary untouched: {path}")


def remove_verifier(nos3_root: Path) -> None:
    candidates = [
        nos3_root / "gsw/cosmos/config/targets/MISSION/procedures" / VERIFY_SCRIPT_NAME,
        nos3_root / "gsw/cosmos/outputs/tmp/config/targets/MISSION/procedures" / VERIFY_SCRIPT_NAME,
    ]

    for path in candidates:
        remove_path(nos3_root, path)


def remove_container_verifier(operator_container: str) -> None:
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        print(f"Skipped container verifier cleanup; docker ps failed: {result.stderr.strip()}")
        return

    containers = {line.strip() for line in result.stdout.splitlines()}
    if operator_container not in containers:
        print(f"Skipped container verifier cleanup; {operator_container} is not running.")
        return

    result = subprocess.run(
        ["docker", "exec", operator_container, "rm", "-f", f"/tmp/{VERIFY_SCRIPT_NAME}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode == 0:
        print(f"Removed container verifier: {operator_container}:/tmp/{VERIFY_SCRIPT_NAME}")
    else:
        print(f"Skipped container verifier cleanup; docker exec failed: {result.stderr.strip()}")


def remove_build_and_runtime_artifacts(nos3_root: Path) -> None:
    paths = [
        nos3_root / "fsw/build/exe/cpu1/cf/sp001_sb_spoof.so",
        nos3_root / "fsw/build/exe/cpu1/cf/sp001_tbl.tbl",
        nos3_root / "fsw/build/amd64-nos3/default_cpu1/apps/sp001_sb_spoof",
    ]

    for path in paths:
        remove_path(nos3_root, path)

    cf_dir = nos3_root / "fsw/build/exe/cpu1/cf"
    if cf_dir.exists():
        for path in cf_dir.glob("sp001_*"):
            remove_path(nos3_root, path)


def remove_path(nos3_root: Path, path: Path) -> None:
    if not path.exists():
        print(f"Already absent: {path}")
        return

    ensure_under(nos3_root, path)

    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()

    print(f"Removed: {path}")


def ensure_under(root: Path, path: Path) -> None:
    root = root.resolve()
    path = path.resolve()

    if root == path or root not in path.parents:
        raise SystemExit(f"Refusing to remove path outside NOS3 root: {path}")


if __name__ == "__main__":
    main()
