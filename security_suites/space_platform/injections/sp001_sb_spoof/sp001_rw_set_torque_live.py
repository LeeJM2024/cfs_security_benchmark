#!/usr/bin/env python3
"""Verify SP001 RW torque spoofing from the real NOS3 UART link.

The Generic Reaction Wheel application publishes housekeeping on the cFE
Software Bus, but some NOS3/OpenC3 runs retain a stale decoded copy of that
packet after a cFS restart even while TO_LAB is forwarding the actual datagram.
This runner deliberately does not treat that stale cache as evidence.  It
uses the reaction-wheel simulator's command/reply log, which is the real
downstream UART interface reached by the target cFS application.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


PROFILE_ID = 20
WHEEL = 0
TORQUE = 25
TORQUE_NM = TORQUE / 10000.0


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}")
    return result


def cosmos_command(container: str, command: str, *, tolerate_error: bool = False) -> str:
    script = "\n".join(
        [
            "require 'cosmos'",
            "require 'cosmos/script'",
            "include Cosmos::Script",
            f"cmd({command!r})",
        ]
    )
    result = run(["docker", "exec", container, "/usr/bin/ruby", "-e", script], check=not tolerate_error)
    return result.stdout


def docker_logs(container: str, since: str) -> str:
    return run(["docker", "logs", "--since", since, container], check=False).stdout


def wait_for_log(container: str, since: str, pattern: re.Pattern[str], timeout: float) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        last = docker_logs(container, since)
        if pattern.search(last):
            return True, last
        time.sleep(0.4)
    return False, last


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SP001 profile 20 and verify the real RW UART command/recovery link")
    parser.add_argument("--operator-container", default="cosmos-openc3-operator-1")
    parser.add_argument("--fsw-container", default="sc01-nos-fsw")
    parser.add_argument("--rw-sim-container", default="sc01-rw-sim0")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--report-dir", type=Path)
    args = parser.parse_args()

    started = datetime.now(timezone.utc)
    since = started.isoformat(timespec="seconds")
    report_dir = args.report_dir or Path("security_suites/space_platform/injections/sp001_sb_spoof/results") / started.strftime(
        "%Y%m%dT%H%M%SZ"
    )
    report_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, object] = {
        "benchmark_id": "SP001",
        "profile": "rw_set_torque",
        "profile_id": PROFILE_ID,
        "attack_success_semantics": "PASS means the spoofed command reached the real RW UART interface",
        "started_at": started.isoformat(),
        "target": "GENERIC_REACTION_WHEEL -> sc01-rw-sim0",
        "attack_torque_nm": TORQUE_NM,
    }
    attack_dispatched = False
    recovery_attempted = False

    try:
        # Starting an already-active benchmark app is benign; its subsequent
        # reset command is the actual readiness check.
        cosmos_command(
            args.operator_container,
            "CFS CFE_ES_START_APP with APPLICATION SP001_SPOOFER, APPENTRYPOINT SP001_AppMain, "
            "APPFILENAME /cf/sp001_sb_spoof.so, STACKSIZE 32768, EXCEPTIONACTION 0, PRIORITY 90",
            tolerate_error=True,
        )
        time.sleep(1.0)
        result["reset"] = cosmos_command(args.operator_container, "CFS SP001_RESET")
        result["attack_command"] = cosmos_command(
            args.operator_container,
            "CFS SP001_RUN_PROFILE with PROFILEID 20, FLAGS 0, ARG1 0, ARG2 25, ARG3 0, ARG4 0",
        )
        attack_dispatched = True

        attack_pattern = re.compile(r"REQUEST SET_TORQUE=\s*0\.0025.*?REPLY\s+SET_TORQUE=.*?0\.0025", re.DOTALL)
        attack_seen, attack_log = wait_for_log(args.rw_sim_container, since, attack_pattern, args.timeout)
        fsw_log = docker_logs(args.fsw_container, since)
        result["attack"] = {
            "profile_event_seen": "SP001: profile 20 spoof transmitted" in fsw_log,
            "uart_set_torque_and_reply_seen": attack_seen,
            "rw_sim_log": attack_log,
        }

        result["recovery_command"] = cosmos_command(
            args.operator_container,
            "GENERIC_REACTION_WHEEL GENERIC_RW_SET_TORQUE_CC with WHEEL_NUMBER 0, TORQUE 0",
        )
        recovery_attempted = True
        recovery_pattern = re.compile(r"REQUEST SET_TORQUE=\s*0\.0000.*?REPLY\s+SET_TORQUE=.*?= 0(?:\.0+)?", re.DOTALL)
        recovery_seen, recovery_log = wait_for_log(args.rw_sim_container, since, recovery_pattern, args.timeout)
        result["recovery"] = {"uart_zero_and_reply_seen": recovery_seen, "rw_sim_log": recovery_log}

        result["passed"] = bool(result["attack"]["profile_event_seen"] and attack_seen and recovery_seen)  # type: ignore[index]
    except Exception as error:  # retain diagnostic details in the benchmark artifact
        result["passed"] = False
        result["error_type"] = type(error).__name__
        result["error"] = str(error)
    finally:
        # A failed observation must never leave the bounded non-zero torque
        # command in place.  This is intentionally independent of PASS/FAIL.
        if attack_dispatched and not recovery_attempted:
            try:
                result["emergency_recovery_command"] = cosmos_command(
                    args.operator_container,
                    "GENERIC_REACTION_WHEEL GENERIC_RW_SET_TORQUE_CC with WHEEL_NUMBER 0, TORQUE 0",
                )
            except Exception as recovery_error:
                result["emergency_recovery_error"] = f"{type(recovery_error).__name__}: {recovery_error}"

    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    report_path = report_dir / "rw_set_torque_live_score.json"
    report_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"SP001 rw_set_torque live UART verification: {'PASS' if result['passed'] else 'FAIL'}")
    print(f"Report: {report_path}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
