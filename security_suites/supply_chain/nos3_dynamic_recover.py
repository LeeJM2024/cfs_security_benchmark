#!/usr/bin/env python3
"""Recover the NOS3 dynamic-NOVATEL test path without touching CmdTlmServer.

This helper is intentionally limited to the local NOS3 simulation containers:
the NOS Engine, GPS simulator, cFS flight software, and time driver.  It does
not start, stop, restart, or otherwise manage COSMOS/CmdTlmServer.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Sequence


ENGINE = "sc01-nos-engine-server"
GPS = "sc01-gps-sim"
FSW = "sc01-nos-fsw"
TIME_DRIVER = "nos-time-driver"

MANAGED_CONTAINERS = (ENGINE, GPS, FSW, TIME_DRIVER)
READY_LOG_MARKERS = (
    "CFE_ES_Main entering OPERATIONAL state",
    "CI_LAB listening on UDP port: 5012",
    "TO Lab Initialized",
)


class RecoveryError(RuntimeError):
    """The local NOS3 recovery could not establish a required condition."""


def run(command: Sequence[str], *, dry_run: bool = False, check: bool = True) -> subprocess.CompletedProcess[str]:
    printable = " ".join(command)
    print(f"$ {printable}")
    if dry_run:
        return subprocess.CompletedProcess(command, 0, "", "")
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no diagnostic output"
        raise RecoveryError(f"Command failed ({completed.returncode}): {printable}\n{detail}")
    return completed


def is_running(container: str, *, dry_run: bool) -> bool:
    completed = run(
        ["docker", "inspect", "--format", "{{.State.Running}}", container],
        dry_run=dry_run,
        check=not dry_run,
    )
    return dry_run or completed.stdout.strip().lower() == "true"


def stop_if_running(container: str, *, dry_run: bool) -> None:
    if dry_run:
        run(["docker", "stop", "--time", "15", container], dry_run=True)
        return
    if is_running(container, dry_run=dry_run):
        run(["docker", "stop", "--time", "15", container], dry_run=dry_run)
    else:
        print(f"# {container} is already stopped")


def start_if_stopped(container: str, *, dry_run: bool) -> None:
    if dry_run:
        run(["docker", "start", container], dry_run=True)
        return
    if not is_running(container, dry_run=dry_run):
        run(["docker", "start", container], dry_run=dry_run)
    else:
        print(f"# {container} is already running")


def restart_engine(*, dry_run: bool) -> None:
    if is_running(ENGINE, dry_run=dry_run):
        run(["docker", "restart", ENGINE], dry_run=dry_run)
    else:
        run(["docker", "start", ENGINE], dry_run=dry_run)


def fsw_logs() -> str:
    completed = run(["docker", "logs", "--tail", "600", FSW], check=False)
    return (completed.stdout + "\n" + completed.stderr).replace("\r", "")


def wait_for_fsw_ready(timeout_seconds: float, *, dry_run: bool) -> dict[str, bool]:
    if dry_run:
        return {marker: True for marker in READY_LOG_MARKERS}

    deadline = time.monotonic() + timeout_seconds
    observed = {marker: False for marker in READY_LOG_MARKERS}
    while time.monotonic() < deadline:
        if not is_running(FSW, dry_run=False):
            raise RecoveryError(f"{FSW} stopped while waiting for cFE readiness")
        logs = fsw_logs()
        for marker in observed:
            observed[marker] = observed[marker] or marker in logs
        if all(observed.values()):
            return observed
        time.sleep(1.0)
    missing = [marker for marker, present in observed.items() if not present]
    raise RecoveryError(f"FSW did not become ready within {timeout_seconds:g}s; missing log markers: {missing}")


def recover(args: argparse.Namespace) -> dict[str, object]:
    # Deliberate order: clear simulated-time and UART state, restart the engine,
    # register GPS first, then let cFS open its UART, and only then advance time.
    stop_if_running(TIME_DRIVER, dry_run=args.dry_run)
    stop_if_running(FSW, dry_run=args.dry_run)
    stop_if_running(GPS, dry_run=args.dry_run)

    restart_engine(dry_run=args.dry_run)
    start_if_stopped(GPS, dry_run=args.dry_run)
    if not args.dry_run:
        time.sleep(args.gps_settle_seconds)
    start_if_stopped(FSW, dry_run=args.dry_run)
    if not args.dry_run:
        time.sleep(args.fsw_settle_seconds)
    start_if_stopped(TIME_DRIVER, dry_run=args.dry_run)

    readiness = wait_for_fsw_ready(args.ready_timeout, dry_run=args.dry_run)
    running = {name: is_running(name, dry_run=args.dry_run) for name in MANAGED_CONTAINERS}
    if not all(running.values()):
        failed = [name for name, active in running.items() if not active]
        raise RecoveryError(f"Recovery sequence completed but containers are not running: {failed}")

    return {
        "recovered": True,
        "dry_run": args.dry_run,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "managed_containers": running,
        "fsw_readiness": readiness,
        "cmdtlmserver_touched": False,
        "note": "This checks NOS3 infrastructure readiness. Run a declared dynamic benchmark profile to prove live NOVATEL telemetry.",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Print the recovery actions without changing containers")
    parser.add_argument("--gps-settle-seconds", type=float, default=3.0, help="Delay after GPS starts (default: 3)")
    parser.add_argument("--fsw-settle-seconds", type=float, default=3.0, help="Delay after FSW starts before time resumes (default: 3)")
    parser.add_argument("--ready-timeout", type=float, default=45.0, help="Maximum wait for cFE/CI/TO readiness (default: 45)")
    parser.add_argument("--json", action="store_true", help="Print the final recovery result as JSON")
    args = parser.parse_args()
    if args.gps_settle_seconds < 0 or args.fsw_settle_seconds < 0 or args.ready_timeout <= 0:
        parser.error("settle delays must be non-negative and --ready-timeout must be positive")
    return args


def main() -> int:
    args = parse_args()
    try:
        result = recover(args)
    except RecoveryError as error:
        result = {
            "recovered": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cmdtlmserver_touched": False,
            "error": str(error),
        }
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"RECOVERY FAILED: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("RECOVERY READY: Engine, GPS, FSW, and time-driver are running; cFE/CI/TO readiness confirmed.")
        print("CmdTlmServer was not touched.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
