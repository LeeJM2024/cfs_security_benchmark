#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


COMPONENT_PATH = "sp003_app_crash_restart/fsw/cfs"
APP_ENTRY = f"        {COMPONENT_PATH}\n"
COMPONENT_NAME = "sp003_app_crash_restart"
COSMOS_DICT_NAME = "SP003_APP_CRASH_RESTART.txt"
VERIFY_SCRIPT_NAME = "sp003_verify.rb"
DEFAULT_OPERATOR_CONTAINER = "cosmos-openc3-operator-1"
DEFAULT_NOS3_ROOT = Path("/home/leejm/nos3")


def main() -> None:
    args = parse_args()
    nos3_root = resolve_nos3_root(args.nos3_root)
    integration_root = Path(__file__).resolve().parent

    if not (integration_root / "components" / COMPONENT_NAME).exists():
        raise SystemExit(f"Missing SP003 component source: {integration_root / 'components' / COMPONENT_NAME}")
    if not (integration_root / "gsw/cosmos/cmd_tlm" / COSMOS_DICT_NAME).exists():
        raise SystemExit(f"Missing SP003 COSMOS/OpenC3 dictionary: {integration_root / 'gsw/cosmos/cmd_tlm' / COSMOS_DICT_NAME}")
    if not (integration_root / VERIFY_SCRIPT_NAME).exists():
        print(f"SP003 verifier not present yet: {integration_root / VERIFY_SCRIPT_NAME}")

    copy_component(integration_root, nos3_root)
    install_cosmos_dictionary(integration_root, nos3_root)
    if (integration_root / VERIFY_SCRIPT_NAME).exists():
        install_verifier(integration_root, nos3_root, args.operator_container)
    update_targets(nos3_root / "cfg/nos3_defs/targets.cmake")

    build_targets = nos3_root / "cfg/build/nos3_defs/targets.cmake"
    if build_targets.exists():
        update_targets(build_targets)

    print("SP003 app crash/restart pressure integration installed.")
    print("")
    print("Benchmark workflow:")
    print("  1. prepare/install: copy SP003 FSW app, install COSMOS dictionary, update targets.cmake")
    print("  2. build:           run `make config && make fsw` once from NOS3 root")
    print("  3. run/verify:      launch NOS3, then run the installed SP003 verifier")
    print("  4. uninstall:       run uninstall_from_nos3.py after benchmark testing is complete")
    print("")
    print("Verifier command after launch:")
    print("  docker exec cosmos-openc3-operator-1 /usr/bin/ruby /tmp/sp003_verify.rb")
    print("")
    print("Hazardous profile command:")
    print("  docker exec -e SP003_MODE=hazardous -e SP003_CONFIRM_HAZARD=YES cosmos-openc3-operator-1 /usr/bin/ruby /tmp/sp003_verify.rb")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install SP003 cFS app crash/restart pressure benchmark artifacts into a NOS3 source tree."
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
        help="OpenC3/COSMOS operator container name used for optional /tmp verifier copy.",
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


def copy_component(integration_root: Path, nos3_root: Path) -> None:
    source = integration_root / "components" / COMPONENT_NAME
    destination = nos3_root / "components" / COMPONENT_NAME

    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
    print(f"Installed component: {destination}")


def install_cosmos_dictionary(integration_root: Path, nos3_root: Path) -> None:
    source = integration_root / "gsw/cosmos/cmd_tlm" / COSMOS_DICT_NAME
    destinations = [
        nos3_root / "gsw/cosmos/config/targets/CFS/cmd_tlm" / COSMOS_DICT_NAME,
    ]

    generated = nos3_root / "gsw/cosmos/outputs/tmp/config/targets/CFS/cmd_tlm"
    if generated.exists():
        destinations.append(generated / COSMOS_DICT_NAME)

    for destination in destinations:
        destination.parent.mkdir(parents=True, exist_ok=True)
        backup_once(destination)
        shutil.copy2(source, destination)
        print(f"Installed COSMOS/OpenC3 dictionary: {destination}")


def install_verifier(integration_root: Path, nos3_root: Path, operator_container: str) -> None:
    source = integration_root / VERIFY_SCRIPT_NAME
    destinations = [
        nos3_root / "gsw/cosmos/config/targets/MISSION/procedures" / VERIFY_SCRIPT_NAME,
    ]

    generated = nos3_root / "gsw/cosmos/outputs/tmp/config/targets/MISSION/procedures"
    if generated.exists():
        destinations.append(generated / VERIFY_SCRIPT_NAME)

    for destination in destinations:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        print(f"Installed COSMOS/OpenC3 verifier: {destination}")

    copy_verifier_to_operator_container(source, operator_container)


def copy_verifier_to_operator_container(source: Path, operator_container: str) -> None:
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        print(f"Skipped container verifier copy; docker ps failed: {result.stderr.strip()}")
        return

    containers = {line.strip() for line in result.stdout.splitlines()}
    if operator_container not in containers:
        print(f"Skipped container verifier copy; {operator_container} is not running.")
        return

    result = subprocess.run(
        ["docker", "cp", str(source), f"{operator_container}:/tmp/{VERIFY_SCRIPT_NAME}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode == 0:
        print(f"Copied verifier into {operator_container}:/tmp/{VERIFY_SCRIPT_NAME}")
    else:
        print(f"Skipped container verifier copy; docker cp failed: {result.stderr.strip()}")


def backup_once(path: Path) -> None:
    if not path.exists():
        return

    backup = path.with_suffix(path.suffix + ".sp003.bak")
    if not backup.exists():
        shutil.copy2(path, backup)


def update_targets(path: Path) -> None:
    backup_once(path)
    text = path.read_text(encoding="utf-8")
    text = normalize_targets_entry(text)

    if has_standalone_targets_entry(text):
        path.write_text(text, encoding="utf-8")
        print(f"targets.cmake already contains {COMPONENT_NAME}: {path}")
        return

    marker = "list(APPEND MISSION_GLOBAL_APPLIST"
    start = text.find(marker)
    if start == -1:
        raise SystemExit(f"Could not find MISSION_GLOBAL_APPLIST in {path}")

    end = text.find("\n)", start)
    if end == -1:
        raise SystemExit(f"Could not find end of MISSION_GLOBAL_APPLIST in {path}")

    text = text[:end] + "\n" + APP_ENTRY.rstrip("\n") + text[end:]
    path.write_text(text, encoding="utf-8")
    print(f"Updated targets.cmake: {path}")


def normalize_targets_entry(text: str) -> str:
    lines = []
    changed = False

    for line in text.splitlines(keepends=True):
        if COMPONENT_PATH not in line:
            lines.append(line)
            continue

        newline = "\n" if line.endswith("\n") else ""
        body = line[:-1] if newline else line
        prefix = body.replace(COMPONENT_PATH, "").rstrip()

        if prefix:
            lines.append(prefix + newline)
            lines.append(APP_ENTRY)
            changed = True
        else:
            lines.append(APP_ENTRY)
            changed = changed or body != APP_ENTRY.rstrip("\n")

    return "".join(lines) if changed else text


def has_standalone_targets_entry(text: str) -> bool:
    return any(line.strip() == COMPONENT_PATH for line in text.splitlines())


if __name__ == "__main__":
    main()
