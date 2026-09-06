#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
from pathlib import Path


COMPONENTS = ("sc_vendor_nav", "sc_vendor_diag")
PAYLOAD_SOURCES = {
    "sc_vendor_nav": (
        ("sp001_sb_spoof", "components/sp001_sb_spoof/fsw/cfs/src/sp001_sb_spoof_targets.c"),
        ("sp001_sb_spoof", "components/sp001_sb_spoof/fsw/cfs/src/sp001_sb_spoof_targets.h"),
        ("sp001_sb_spoof", "components/sp001_sb_spoof/fsw/cfs/src/sp001_sb_spoof_msg.h"),
        ("sp001_sb_spoof", "components/sp001_sb_spoof/fsw/cfs/src/sp001_sb_spoof_events.h"),
        ("sp001_sb_spoof", "components/sp001_sb_spoof/fsw/cfs/mission_inc/sp001_sb_spoof_perfids.h"),
        ("sp001_sb_spoof", "components/sp001_sb_spoof/fsw/cfs/platform_inc/sp001_sb_spoof_msgids.h"),
        ("sp003_app_crash_restart", "components/sp003_app_crash_restart/fsw/cfs/src/sp003_app_crash_restart_app.c"),
        ("sp003_app_crash_restart", "components/sp003_app_crash_restart/fsw/cfs/src/sp003_app_crash_restart_app.h"),
        ("sp003_app_crash_restart", "components/sp003_app_crash_restart/fsw/cfs/src/sp003_app_crash_restart_msg.h"),
        ("sp003_app_crash_restart", "components/sp003_app_crash_restart/fsw/cfs/src/sp003_app_crash_restart_events.h"),
        ("sp003_app_crash_restart", "components/sp003_app_crash_restart/fsw/cfs/mission_inc/sp003_app_crash_restart_perfids.h"),
        ("sp003_app_crash_restart", "components/sp003_app_crash_restart/fsw/cfs/platform_inc/sp003_app_crash_restart_msgids.h"),
        ("sp006_payload_critical_interface_abuse", "components/sp006_payload_abuse/fsw/cfs/src/sp006_payload_abuse_profiles.c"),
        ("sp006_payload_critical_interface_abuse", "components/sp006_payload_abuse/fsw/cfs/src/sp006_payload_abuse_profiles.h"),
        ("sp006_payload_critical_interface_abuse", "components/sp006_payload_abuse/fsw/cfs/src/sp006_payload_abuse_msg.h"),
        ("sp006_payload_critical_interface_abuse", "components/sp006_payload_abuse/fsw/cfs/src/sp006_payload_abuse_events.h"),
        ("sp007_resource_exhaustion", "components/sp007_resource_exhaustion/fsw/cfs/src/sp007_resource_exhaustion_profiles.c"),
        ("sp007_resource_exhaustion", "components/sp007_resource_exhaustion/fsw/cfs/src/sp007_resource_exhaustion_profiles.h"),
        ("sp007_resource_exhaustion", "components/sp007_resource_exhaustion/fsw/cfs/src/sp007_resource_exhaustion_msg.h"),
        ("sp007_resource_exhaustion", "components/sp007_resource_exhaustion/fsw/cfs/src/sp007_resource_exhaustion_app.c"),
        ("sp007_resource_exhaustion", "components/sp007_resource_exhaustion/fsw/cfs/src/sp007_resource_exhaustion_app.h"),
        ("sp007_resource_exhaustion", "components/sp007_resource_exhaustion/fsw/cfs/src/sp007_resource_exhaustion_events.h"),
        ("sp007_resource_exhaustion", "components/sp007_resource_exhaustion/fsw/cfs/mission_inc/sp007_resource_exhaustion_perfids.h"),
        ("sp007_resource_exhaustion", "components/sp007_resource_exhaustion/fsw/cfs/platform_inc/sp007_resource_exhaustion_msgids.h"),
        ("sp008_subsystem_state_spoof", "components/sp008_state_spoof/fsw/cfs/src/sp008_state_spoof_app.c"),
        ("sp008_subsystem_state_spoof", "components/sp008_state_spoof/fsw/cfs/src/sp008_state_spoof_app.h"),
        ("sp008_subsystem_state_spoof", "components/sp008_state_spoof/fsw/cfs/src/sp008_state_spoof_msg.h"),
        ("sp008_subsystem_state_spoof", "components/sp008_state_spoof/fsw/cfs/src/sp008_state_spoof_events.h"),
        ("sp008_subsystem_state_spoof", "components/sp008_state_spoof/fsw/cfs/mission_inc/sp008_state_spoof_perfids.h"),
        ("sp008_subsystem_state_spoof", "components/sp008_state_spoof/fsw/cfs/platform_inc/sp008_state_spoof_msgids.h"),
    )
}
TARGET_ENTRIES = tuple(f"        {name}/fsw/cfs" for name in COMPONENTS)
STARTUP_ENTRIES = (
    "CFE_APP, sc_vendor_nav,                 SCVN_AppMain,              SC_VENDOR_NAV,    79, 32768, 0x0, 0;",
    "CFE_APP, sc_vendor_diag,                SCVD_AppMain,              SC_VENDOR_DIAG,   80, 32768, 0x0, 0;",
)
DICT_FILES = tuple(f"{name.upper()}.txt" for name in COMPONENTS)
VERIFY_SCRIPT_NAME = "sc_vendor_verify.rb"
DEFAULT_NOS3_ROOT = Path("/home/leejm/nos3")
TO_LAB_SUB_RELATIVES = (
    "cfg/nos3_defs/tables/to_lab_sub.c",
    "cfg/build/nos3_defs/tables/to_lab_sub.c",
)
VALID_NOVATEL_FILE = Path("cfg/sims/gps_data.42")
VALID_NOVATEL_LINE = (
    "900000000.0 4500000.0 2000000.0 4800000.0 "
    "4500000.0 2000000.0 4800000.0 0.0 0.0 0.0 0.0 0.0 0.0\n"
)
GPS_SIM_CONFIG_RELATIVES = (
    "cfg/sims/nos3-simulator.xml",
    "cfg/sims/nos3-simulator.sockets.xml",
    "cfg/sims/nos3-simulator.shmem.xml",
    "cfg/build/sims/nos3-simulator.xml",
    "cfg/build/sims/nos3-simulator.sockets.xml",
    "cfg/build/sims/nos3-simulator.shmem.xml",
    "sims/build/nos3-simulator.xml",
    "sims/build/nos3-simulator.sockets.xml",
    "sims/build/nos3-simulator.shmem.xml",
    "sims/build/bin/nos3-simulator.xml",
    "sims/build/bin/nos3-simulator.sockets.xml",
    "sims/build/bin/nos3-simulator.shmem.xml",
)
GPS_DATA_RELATIVES = (
    "cfg/sims/gps_data.42",
    "cfg/build/sims/gps_data.42",
    "sims/build/gps_data.42",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Install supply-chain vendor apps into NOS3")
    parser.add_argument("--nos3-root", type=Path, default=DEFAULT_NOS3_ROOT)
    parser.add_argument("--prepare-valid-novatel", action="store_true")
    args = parser.parse_args()
    root = args.nos3_root.expanduser().resolve()
    require_nos3(root)
    source_root = Path(__file__).resolve().parent
    if args.prepare_valid_novatel:
        prepare_valid_novatel(root)

    for component in COMPONENTS:
        source = source_root / "components" / component
        destination = root / "components" / component
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(source, destination)
        for namespace, relative in PAYLOAD_SOURCES.get(component, ()):
            payload_source = source_root / ".." / "space_platform" / "injections" / namespace / relative
            payload_destination = destination / "fsw/cfs/src/payload_adapters" / Path(relative).name
            payload_destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(payload_source, payload_destination)
        print(f"installed component: {destination}")

    for dictionary in DICT_FILES:
        source = source_root / "components" / dictionary.lower().replace(".txt", "") / "gsw/cosmos/cmd_tlm" / dictionary
        destination = root / "gsw/cosmos/config/targets/CFS/cmd_tlm" / dictionary
        destination.parent.mkdir(parents=True, exist_ok=True)
        backup_once(destination)
        shutil.copy2(source, destination)
        print(f"installed dictionary: {destination}")

    verifier = root / "gsw/cosmos/config/targets/MISSION/procedures" / VERIFY_SCRIPT_NAME
    verifier.parent.mkdir(parents=True, exist_ok=True)
    backup_once(verifier)
    shutil.copy2(source_root / VERIFY_SCRIPT_NAME, verifier)
    print(f"installed verifier: {verifier}")

    for path in _target_files(root):
        backup_once(path)
        update_targets(path)
        print(f"updated integration file: {path}")
    for path in _startup_files(root):
        backup_once(path)
        update_startup(path)
        print(f"updated integration file: {path}")
    for relative in TO_LAB_SUB_RELATIVES:
        path = root / relative
        if path.exists():
            backup_once(path)
            update_to_lab_subscriptions(path)
            print(f"updated TO_LAB subscription table: {path}")

    print("Supply-chain vendor app installation complete.")
    print("Run `make config && make fsw`, then launch NOS3 before live verification.")


def require_nos3(root: Path) -> None:
    if not (root / "cfg/nos3_defs/targets.cmake").is_file() or not (root / "gsw/cosmos").is_dir():
        raise SystemExit(f"{root} does not look like a NOS3 repository root")


def prepare_valid_novatel(root: Path) -> None:
    """Opt-in finite GPSFILE preparation for dynamic NOVATEL profiles."""
    for relative in GPS_DATA_RELATIVES:
        data_file = root / relative
        backup_once(data_file)
        data_file.parent.mkdir(parents=True, exist_ok=True)
        data_file.write_text(VALID_NOVATEL_LINE * 256, encoding="ascii")
    for relative in GPS_SIM_CONFIG_RELATIVES:
        path = root / relative
        if not path.exists():
            continue
        if set_novatel_provider(path, "GPSFILE"):
            print(f"prepared finite NOVATEL GPSFILE source: {path}")


def set_novatel_provider(path: Path, provider: str) -> bool:
    """Replace only GPS simulator's data provider, preserving the rest of the XML."""
    text = path.read_text(encoding="utf-8")
    gps_start = text.find("<name>gps</name>")
    if gps_start < 0:
        return False
    begin = text.find("<data-provider", gps_start)
    end = text.find("</data-provider>", begin)
    if begin < 0 or end < 0:
        return False
    end += len("</data-provider>")
    if provider == "GPSFILE":
        replacement = (
            "<data-provider>\n"
            "                    <type>GPSFILE</type>\n"
            "                    <filename>/home/leejm/nos3/sims/build/gps_data.42</filename>\n"
            "                    <leap-seconds>37</leap-seconds>\n"
            "                </data-provider>"
        )
    elif provider == "GPS42SOCKET":
        replacement = (
            "<data-provider>\n"
            "                    <type>GPS42SOCKET</type>\n"
            "                    <hostname>fortytwo</hostname>\n"
            "                    <port>4245</port>\n"
            "                    <max-connection-attempts>30</max-connection-attempts>\n"
            "                    <retry-wait-seconds>1</retry-wait-seconds>\n"
            "                    <spacecraft>0</spacecraft>\n"
            "                    <GPS>0</GPS>\n"
            "                    <leap-seconds>37</leap-seconds>\n"
            "                </data-provider>"
        )
    else:
        raise ValueError(f"Unsupported NOVATEL provider: {provider}")
    path.write_text(text[:begin] + replacement + text[end:], encoding="utf-8")
    return True


def _target_files(root: Path) -> list[Path]:
    paths = [root / "cfg/nos3_defs/targets.cmake"]
    for relative in ("cfg/build/nos3_defs/targets.cmake",):
        path = root / relative
        if path.exists():
            paths.append(path)
    return paths


def _startup_files(root: Path) -> list[Path]:
    paths = [
        root / "cfg/nos3_defs/cpu1_cfe_es_startup.scr",
    ]
    for relative in (
        "cfg/build/nos3_defs/cpu1_cfe_es_startup.scr",
        "fsw/build/exe/cpu1/cf/cfe_es_startup.scr",
    ):
        path = root / relative
        if path.exists():
            paths.append(path)
    return paths


def update_targets(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for entry in TARGET_ENTRIES:
        if entry not in text:
            marker = "list(APPEND MISSION_GLOBAL_APPLIST"
            start = text.find(marker)
            end = text.find("\n)", start)
            if start < 0 or end < 0:
                raise SystemExit(f"could not find MISSION_GLOBAL_APPLIST in {path}")
            text = text[:end] + f"\n{entry}" + text[end:]
    path.write_text(text, encoding="utf-8")


def update_startup(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    # Replace an earlier installation so entry-point fixes do not accumulate
    # duplicate CFE_APP records in generated startup scripts.
    lines = [
        line
        for line in text.splitlines()
        if not line.lstrip().startswith(("CFE_APP, sc_vendor_nav,", "CFE_APP, sc_vendor_diag,"))
    ]
    text = "\n".join(lines) + "\n"
    for entry in STARTUP_ENTRIES:
        if entry not in text:
            marker = "\n!"
            index = text.find(marker)
            if index < 0:
                raise SystemExit(f"could not find startup section terminator in {path}")
            text = text[:index].rstrip() + f"\n{entry}" + text[index:]
    path.write_text(text, encoding="utf-8")


def update_to_lab_subscriptions(path: Path) -> None:
    """Route vendor-app HK packets through the real TO_LAB downlink."""
    text = path.read_text(encoding="utf-8")
    include_marker = '#include "syn_msgids.h"'
    if '#include "sc_vendor_nav_msgids.h"' not in text:
        if include_marker not in text:
            raise SystemExit(f"could not find TO_LAB include marker in {path}")
        text = text.replace(
            include_marker,
            include_marker + '\n#include "sc_vendor_nav_msgids.h"\n#include "sc_vendor_diag_msgids.h"',
            1,
        )

    subscription_marker = '        /* Component Specifics */'
    if 'SC_VENDOR_NAV_HK_TLM_MID' not in text:
        if subscription_marker not in text:
            raise SystemExit(f"could not find TO_LAB subscription marker in {path}")
        entries = (
            '        {CFE_SB_MSGID_WRAP_VALUE(SC_VENDOR_NAV_HK_TLM_MID), {0,0}, 32},\n'
            '        {CFE_SB_MSGID_WRAP_VALUE(SC_VENDOR_DIAG_HK_TLM_MID), {0,0}, 32},'
        )
        text = text.replace(subscription_marker, subscription_marker + '\n' + entries, 1)
    path.write_text(text, encoding="utf-8")


def backup_once(path: Path) -> None:
    if not path.exists():
        return
    backup = path.with_suffix(path.suffix + ".sc_supply_chain.bak")
    if not backup.exists():
        shutil.copy2(path, backup)


if __name__ == "__main__":
    main()
