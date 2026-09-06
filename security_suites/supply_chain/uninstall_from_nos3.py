#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from install_into_nos3 import GPS_DATA_RELATIVES, GPS_SIM_CONFIG_RELATIVES, set_novatel_provider


COMPONENTS = ("sc_vendor_nav", "sc_vendor_diag")
TARGET_MARKERS = tuple(f"{name}/fsw/cfs" for name in COMPONENTS)
STARTUP_MARKERS = ("CFE_APP, sc_vendor_nav,", "CFE_APP, sc_vendor_diag,")
DICT_FILES = tuple(f"{name.upper()}.txt" for name in COMPONENTS)
VERIFY_SCRIPT_NAME = "sc_vendor_verify.rb"
DEFAULT_NOS3_ROOT = Path("/home/leejm/nos3")
TO_LAB_SUB_RELATIVES = (
    "cfg/nos3_defs/tables/to_lab_sub.c",
    "cfg/build/nos3_defs/tables/to_lab_sub.c",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Remove supply-chain vendor apps from NOS3")
    parser.add_argument("--nos3-root", type=Path, default=DEFAULT_NOS3_ROOT)
    args = parser.parse_args()
    root = args.nos3_root.expanduser().resolve()
    if not (root / "cfg/nos3_defs/targets.cmake").is_file():
        raise SystemExit(f"{root} does not look like a NOS3 repository root")

    for relative in (
        "cfg/nos3_defs/targets.cmake",
        "cfg/nos3_defs/cpu1_cfe_es_startup.scr",
        "cfg/build/nos3_defs/targets.cmake",
        "cfg/build/nos3_defs/cpu1_cfe_es_startup.scr",
        "fsw/build/exe/cpu1/cf/cfe_es_startup.scr",
    ):
        path = root / relative
        if path.exists():
            remove_marked_lines(path, TARGET_MARKERS, STARTUP_MARKERS)
            remove_backup(path)

    for component in COMPONENTS:
        shutil.rmtree(root / "components" / component, ignore_errors=True)
    for dictionary in DICT_FILES:
        restore_or_remove(root / "gsw/cosmos/config/targets/CFS" / dictionary)
    restore_or_remove(root / "gsw/cosmos/config/targets/MISSION/procedures" / VERIFY_SCRIPT_NAME)
    for relative in TO_LAB_SUB_RELATIVES:
        restore_or_remove(root / relative)
    restore_normal_novatel(root)
    print("Supply-chain vendor app installation removed.")


def remove_marked_lines(path: Path, target_markers: tuple[str, ...], startup_markers: tuple[str, ...]) -> None:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    filtered = [
        line for line in lines
        if not any(marker in line for marker in target_markers + startup_markers)
    ]
    path.write_text("".join(filtered), encoding="utf-8")


def restore_or_remove(path: Path) -> None:
    backup = path.with_suffix(path.suffix + ".sc_supply_chain.bak")
    if backup.exists():
        shutil.copy2(backup, path)
        backup.unlink()
    elif path.exists():
        path.unlink()


def remove_backup(path: Path) -> None:
    backup = path.with_suffix(path.suffix + ".sc_supply_chain.bak")
    if backup.exists():
        backup.unlink()


def restore_normal_novatel(root: Path) -> None:
    """Leave every post-clean NOS3 configuration on its normal 42 socket source."""
    for relative in GPS_SIM_CONFIG_RELATIVES:
        path = root / relative
        if path.exists() and set_novatel_provider(path, "GPS42SOCKET"):
            print(f"restored normal NOVATEL GPS42SOCKET source: {path}")
    for relative in GPS_DATA_RELATIVES:
        restore_or_remove(root / relative)


if __name__ == "__main__":
    main()
