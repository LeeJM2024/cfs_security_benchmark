#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


DEFAULT_OPERATOR_CONTAINER = "cosmos-openc3-operator-1"
DEFAULT_FSW_CONTAINER = "sc01-nos-fsw"
SENDER_SCRIPT_NAME = "sp002_send_malformed_tc.py"
VERIFY_SCRIPT_NAME = "sp002_verify.rb"
HAZARD_MODES = {"hazardous", "short-all", "all"}


def main() -> int:
    args = parse_args()
    integration_root = Path(__file__).resolve().parent

    if args.mode in HAZARD_MODES and not args.confirm_hazard:
        print(
            f"SP002 mode {args.mode!r} includes hazardous profiles; add --confirm-hazard to run it.",
            file=sys.stderr,
        )
        return 2

    to_lab_ip, network_name = discover_to_lab_ip(args.operator_container, args.fsw_container)
    print(f"SP002 auto TO_LAB IP: {to_lab_ip} (shared Docker network: {network_name})", flush=True)

    if not args.no_copy:
        copy_runtime_files(integration_root, args.operator_container)

    cmd = [
        "docker",
        "exec",
        "-e",
        f"SP002_MODE={args.mode}",
        "-e",
        f"SP002_TO_LAB_IP={to_lab_ip}",
    ]

    if args.mode in HAZARD_MODES:
        cmd += ["-e", "SP002_CONFIRM_HAZARD=YES"]
    if args.profile_ids:
        cmd += ["-e", f"SP002_PROFILE_IDS={args.profile_ids}"]
    if args.target:
        cmd += ["-e", f"SP002_TARGET={args.target}"]
    if args.tags:
        cmd += ["-e", f"SP002_TAGS={args.tags}"]
    if args.report_dir:
        cmd += ["-e", f"SP002_REPORT_DIR={args.report_dir}"]

    cmd += [args.operator_container, "/usr/bin/ruby", f"/tmp/{VERIFY_SCRIPT_NAME}"]

    if args.print_only:
        print(shell_join(cmd))
        return 0

    return subprocess.run(cmd).returncode


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run SP002 live verification with automatic TO_LAB telemetry IP discovery."
    )
    parser.add_argument("--mode", choices=("safe", "hazardous", "short-all", "all"), default="safe")
    parser.add_argument("--confirm-hazard", action="store_true", help="required for hazardous, short-all, and all")
    parser.add_argument("--profile-ids", help="comma-separated SP002 profile ids to run")
    parser.add_argument("--target", help="target filter passed to the verifier")
    parser.add_argument("--tags", help="comma-separated tag filters passed to the verifier")
    parser.add_argument("--report-dir", help="explicit report directory inside the operator container")
    parser.add_argument("--operator-container", default=DEFAULT_OPERATOR_CONTAINER)
    parser.add_argument("--fsw-container", default=DEFAULT_FSW_CONTAINER)
    parser.add_argument("--no-copy", action="store_true", help="do not refresh /tmp scripts in the operator container")
    parser.add_argument("--print-only", action="store_true", help="print the docker exec command without running it")
    return parser.parse_args()


def docker_inspect(container: str) -> dict:
    try:
        raw = subprocess.check_output(["docker", "inspect", container], text=True)
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"docker inspect failed for {container}: {error}") from error

    data = json.loads(raw)
    if not data:
        raise SystemExit(f"docker inspect returned no data for {container}")
    return data[0]


def discover_to_lab_ip(operator_container: str, fsw_container: str) -> tuple[str, str]:
    operator_networks = docker_inspect(operator_container)["NetworkSettings"]["Networks"]
    fsw_networks = docker_inspect(fsw_container)["NetworkSettings"]["Networks"]

    shared = [name for name in operator_networks if name in fsw_networks]
    if not shared:
        raise SystemExit(f"No shared Docker network between {operator_container} and {fsw_container}")

    def rank(name: str) -> tuple[int, str]:
        lower = name.lower()
        if "sc" in lower:
            return (0, name)
        if "nos3" in lower:
            return (1, name)
        return (2, name)

    for name in sorted(shared, key=rank):
        ip = operator_networks[name].get("IPAddress", "")
        if ip:
            return ip, name

    raise SystemExit(f"Shared Docker networks have no operator IP: {', '.join(shared)}")


def copy_runtime_files(integration_root: Path, operator_container: str) -> None:
    for name in (SENDER_SCRIPT_NAME, VERIFY_SCRIPT_NAME):
        source = integration_root / name
        if not source.exists():
            raise SystemExit(f"Missing SP002 runtime file: {source}")
        subprocess.run(["docker", "cp", str(source), f"{operator_container}:/tmp/{name}"], check=True)

    subprocess.run(["docker", "exec", operator_container, "chmod", "+x", f"/tmp/{SENDER_SCRIPT_NAME}"], check=True)


def shell_join(argv: list[str]) -> str:
    quoted = []
    for arg in argv:
        if all(ch.isalnum() or ch in "@%_+=:,./-" for ch in arg):
            quoted.append(arg)
        else:
            quoted.append("'" + arg.replace("'", "'\''") + "'")
    return " ".join(quoted)


if __name__ == "__main__":
    raise SystemExit(main())
