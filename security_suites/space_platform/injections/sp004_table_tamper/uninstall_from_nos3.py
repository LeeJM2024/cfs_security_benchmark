#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


COMPONENT_PATH = "sp004_table_tamper/fsw/cfs"
COMPONENT_NAME = "sp004_table_tamper"
COSMOS_DICT_NAME = "SP004_TABLE_TAMPER.txt"
VERIFY_SCRIPT_NAME = "sp004_verify.rb"
TABLE_PAYLOAD_NAMES = [
    "sp004_fm_bad.c",
    "sp004_ds_file_bad.c",
    "sp004_ds_filter_bad.c",
    "sp004_sch_sched_bad.c",
    "sp004_sch_msg_bad.c",
    "sp004_lc_wdt_bad.c",
    "sp004_lc_adt_bad.c",
    "sp004_cf_config_bad.c",
    "sp004_to_config_bad.c",
    "sp004_sc_rts001_bad.c",
    "sp004_sc_ats1_bad.c",
    "sp004_sbn_conf_bad.c",
]
DEFAULT_OPERATOR_CONTAINER = "cosmos-openc3-operator-1"
DEFAULT_NOS3_ROOT = Path("/home/leejm/nos3")
ARCH_HOOK_BEGIN = "# BEGIN SP004_TABLE_TAMPER_BENCHMARK"
ARCH_HOOK_END = "# END SP004_TABLE_TAMPER_BENCHMARK"
BENCHMARK_MARKERS = [
    "SP-004 Table and configuration tampering command interface",
    "SP004 table tamper app",
]


def main() -> None:
    args = parse_args()
    nos3_root = resolve_nos3_root(args.nos3_root)

    remove_targets_entry(nos3_root / "cfg/nos3_defs/targets.cmake")
    remove_arch_build_hook(nos3_root / "cfg/nos3_defs/arch_build_custom.cmake")

    build_targets = nos3_root / "cfg/build/nos3_defs/targets.cmake"
    if build_targets.exists():
        remove_targets_entry(build_targets)
    build_arch_hook = nos3_root / "cfg/build/nos3_defs/arch_build_custom.cmake"
    if build_arch_hook.exists():
        remove_arch_build_hook(build_arch_hook)

    remove_component(nos3_root)
    remove_table_payload_sources(nos3_root)
    remove_cosmos_dictionary(nos3_root)
    remove_verifier(nos3_root)
    remove_container_verifier(args.operator_container)
    remove_build_and_runtime_artifacts(nos3_root)

    print("SP004 table/config tampering integration uninstalled.")
    print("")
    print("Next: run `make config` before the next normal NOS3 build/launch.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Remove SP004 cFS Table Services tampering benchmark artifacts from a NOS3 source tree."
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
        help="OpenC3/COSMOS operator container name used for optional /tmp verifier cleanup.",
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


def remove_arch_build_hook(path: Path) -> None:
    if not path.exists():
        print(f"arch_build_custom.cmake already absent: {path}")
        return

    text = path.read_text(encoding="utf-8")
    start = text.find(ARCH_HOOK_BEGIN)
    end = text.find(ARCH_HOOK_END)

    if start == -1 or end == -1 or end < start:
        print(f"arch_build_custom.cmake did not contain SP004 hook: {path}")
        return

    end += len(ARCH_HOOK_END)
    while end < len(text) and text[end] in "\r\n":
        end += 1

    updated = text[:start].rstrip() + "\n" + text[end:].lstrip("\r\n")
    path.write_text(updated, encoding="utf-8")
    print(f"Removed SP004 table hook from arch_build_custom.cmake: {path}")


def remove_component(nos3_root: Path) -> None:
    remove_path(nos3_root, nos3_root / "components" / COMPONENT_NAME)


def remove_table_payload_sources(nos3_root: Path) -> None:
    candidates = []
    for table_payload_name in TABLE_PAYLOAD_NAMES:
        candidates.extend([
            nos3_root / "cfg/nos3_defs/tables" / table_payload_name,
            nos3_root / "cfg/build/nos3_defs/tables" / table_payload_name,
        ])

    for path in candidates:
        remove_path(nos3_root, path)


def remove_cosmos_dictionary(nos3_root: Path) -> None:
    candidates = [
        nos3_root / "gsw/cosmos/config/targets/CFS/cmd_tlm" / COSMOS_DICT_NAME,
        nos3_root / "gsw/cosmos/outputs/tmp/config/targets/CFS/cmd_tlm" / COSMOS_DICT_NAME,
    ]

    for path in candidates:
        if not path.exists():
            print(f"COSMOS/OpenC3 dictionary already absent: {path}")
            continue

        backup = path.with_suffix(path.suffix + ".sp004.bak")
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
        nos3_root / "fsw/build/exe/cpu1/cf/sp004_tbl_tamper.so",
        nos3_root / "fsw/build/amd64-nos3/default_cpu1/apps/sp004_table_tamper",
    ]

    table_names = [name.replace(".c", ".tbl") for name in TABLE_PAYLOAD_NAMES]
    for table_name in table_names:
        paths.extend([
            nos3_root / "fsw/build/exe/cpu1/cf" / table_name,
            nos3_root / "fsw/build/tables/staging/cpu1/cf" / table_name,
        ])

    for path in paths:
        remove_path(nos3_root, path)

    cf_dir = nos3_root / "fsw/build/exe/cpu1/cf"
    if cf_dir.exists():
        for path in cf_dir.glob("sp004_*"):
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
