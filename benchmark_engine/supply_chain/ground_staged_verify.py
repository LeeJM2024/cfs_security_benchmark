"""Real GS002/GS004 observations for already-applied SC-ART releases.

The module never mutates a release file.  GS002 may perform the manifest's
explicitly enabled CmdTlmServer process reload inside the already-running
COSMOS container; GS004 remains operator-checkpointed.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import time
from typing import Any

from benchmark_engine.core.scenario import load_scenario
from benchmark_engine.ground_system.command_dictionary_pollution import (
    RunConfig, _evaluate_attack, _evaluate_recovery, _poll_snapshot, _read_last_command_buffer,
    _send_command, _snapshot,
)
from benchmark_engine.ground_system.ground_configuration_pollution import _same_counter


ROOT = Path(__file__).resolve().parents[2]


def verify(
    adapter: str,
    manifest: dict[str, Any],
    *,
    container: str,
    output_dir: Path,
    auto_restart: bool = False,
) -> dict[str, Any]:
    case = _case(adapter, manifest)
    config = _config(container, output_dir)
    if adapter == "gs002":
        restart = _restart_cmdtlmserver(config) if auto_restart else {"enabled": False, "reason": "operator_checkpoint"}
        if auto_restart and not restart.get("passed"):
            return {"passed": False, "cmdtlmserver_restart": restart, "reason": "cmdtlmserver_restart_failed"}
        setup = [_send_command(container, command) for command in case.get("setup", [])]
        before = _snapshot(case, config)
        sent = _send_command(container, str(case["displayed_command"]))
        encoded = _read_last_command_buffer(container, str(case["displayed_command"]))
        suffix = str(case.get("expected_packet_hex_suffix", "")).lower()
        encoded["matches_expected_suffix"] = bool(encoded.get("packet_hex", "").lower().endswith(suffix))
        after = _poll_snapshot(case, config, before) if sent.get("ok") and before.get("ok") else {}
        observation = _evaluate_attack(case, before, after) if after else {"passed": False, "reason": "pre-command snapshot or command failed"}
        passed = bool(all(item.get("ok") for item in setup)) and bool(sent.get("ok")) and bool(encoded.get("matches_expected_suffix")) and bool(observation.get("passed"))
        return {"passed": passed, "cmdtlmserver_restart": restart, "setup": setup, "before": before, "command": sent, "encoded_command": encoded, "after": after, "mission_effect": observation}
    if adapter == "gs004":
        restart = _restart_cmdtlmserver(config) if auto_restart else {"enabled": False, "reason": "operator_checkpoint"}
        if auto_restart and not restart.get("passed"):
            return {"passed": False, "cmdtlmserver_restart": restart, "reason": "cmdtlmserver_restart_failed"}
        before = _snapshot(case, config)
        sent = _send_command(container, str(case["command"]))
        after = _snapshot(case, config)
        misdirected = _same_counter(before, after)
        telemetry_endpoint_refused = not before.get("ok") and not after.get("ok")
        command_endpoint_refused = not sent.get("ok") and str(sent.get("error_class", "")) == "Errno::ECONNREFUSED"
        delivery_outcome = "command_accepted_but_not_delivered" if sent.get("ok") else "wrong_endpoint_refused"
        if telemetry_endpoint_refused:
            delivery_outcome = "wrong_endpoint_refused_command_or_telemetry"
        # Both outcomes prove the release changed the real delivery boundary:
        # the operator's legitimate command was attempted and cFS did not see it.
        # ECONNREFUSED from the deliberately wrong endpoint is itself the
        # real route-induced delivery denial.  It does not require a stable
        # cFS counter because the command never reached the flight target.
        passed = command_endpoint_refused or telemetry_endpoint_refused or (
            bool(before.get("ok")) and bool(after.get("ok")) and misdirected and bool(sent.get("ok"))
        )
        return {
            "passed": passed, "cmdtlmserver_restart": restart, "before": before, "command": sent, "after": after,
            "delivery_outcome": delivery_outcome,
            "mission_effect": {
                "passed": command_endpoint_refused or misdirected or telemetry_endpoint_refused,
                "reason": "polluted route prevented command delivery or redirected the DEBUG telemetry endpoint",
            },
        }
    raise ValueError(f"Unsupported staged ground adapter: {adapter}")


def recover(
    adapter: str,
    manifest: dict[str, Any],
    *,
    container: str,
    output_dir: Path,
    auto_restart: bool = False,
) -> dict[str, Any]:
    case = _case(adapter, manifest)
    config = _config(container, output_dir)
    if adapter == "gs002":
        restart = _restart_cmdtlmserver(config) if auto_restart else {"enabled": False, "reason": "operator_checkpoint"}
        if auto_restart and not restart.get("passed"):
            return {"passed": False, "cmdtlmserver_restart": restart, "reason": "cmdtlmserver_restart_failed"}
        commands = [_send_command(container, command) for command in case.get("recovery", [])]
        recovered = _snapshot(case, config)
        effect = _evaluate_recovery(case, recovered)
        return {"passed": bool(all(item.get("ok") for item in commands)) and bool(effect.get("passed")), "cmdtlmserver_restart": restart, "commands": commands, "snapshot": recovered, "recovery_effect": effect}
    if adapter == "gs004":
        restart = _restart_cmdtlmserver(config) if auto_restart else {"enabled": False, "reason": "operator_checkpoint"}
        if auto_restart and not restart.get("passed"):
            return {"passed": False, "cmdtlmserver_restart": restart, "reason": "cmdtlmserver_restart_failed"}
        before = _snapshot(case, config)
        sent = _send_command(container, str(case["command"]))
        after = _snapshot(case, config)
        recovered = not _same_counter(before, after)
        return {"passed": bool(sent.get("ok")) and recovered, "cmdtlmserver_restart": restart, "before": before, "command": sent, "after": after, "recovery_effect": {"passed": recovered, "reason": "restored route delivered safe command to cFS"}}
    raise ValueError(f"Unsupported staged ground adapter: {adapter}")


def _case(adapter: str, manifest: dict[str, Any]) -> dict[str, Any]:
    scenario_path = ROOT / ("security_suites/ground_system/scenarios/command_dictionary_pollution.yaml" if adapter == "gs002" else "security_suites/ground_system/scenarios/ground_configuration_pollution.yaml")
    requested = str(manifest["lifecycle"].get("case_id", ""))
    cases = [dict(item) for item in load_scenario(scenario_path).attack["cases"]]
    for case in cases:
        if str(case["id"]) == requested:
            return case
    raise ValueError(f"Manifest case_id {requested!r} is not declared in {scenario_path}")


def _config(container: str, output_dir: Path) -> RunConfig:
    return RunConfig(container=container, output_dir=output_dir, command_server_root="/home/leejm/nos3/gsw/cosmos", timeout_seconds=10.0, server_timeout_seconds=0.0, poll_interval=0.5, settle_seconds=0.5)


def _server_pids(container: str) -> list[str]:
    # CmdTlmServer's GUI process turns into Puma after it starts its JSON DRb
    # services.  The GUI button therefore appears as ``puma ... [cosmos]`` in
    # ps rather than as a long-lived CmdTlmServer process.
    processes: list[str] = []
    for pattern in ("[C]mdTlmServer", r"puma.*\[cosmos\]"):
        result = subprocess.run(
            ["docker", "exec", container, "pgrep", "-af", pattern],
            text=True, capture_output=True, check=False,
        )
        processes.extend(line.strip() for line in result.stdout.splitlines() if line.strip())
    return list(dict.fromkeys(processes))


def _tail_server_log(container: str, path: str) -> str:
    result = subprocess.run(
        ["docker", "exec", container, "tail", "-n", "20", path],
        text=True, capture_output=True, check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else result.stderr.strip()


def _server_ready(processes: list[str]) -> bool:
    return any("puma" in process and "[cosmos]" in process for process in processes)


def _restart_cmdtlmserver(config: RunConfig) -> dict[str, Any]:
    """Reload only CmdTlmServer inside the existing COSMOS container.

    The Launcher button maps to ``ruby tools/CmdTlmServer --config ...``.
    This helper deliberately leaves the Launcher, CmdSender, PacketViewer,
    FSW, and simulator containers untouched.
    """
    container = config.container
    before = _server_pids(container)
    stop = subprocess.run(
        [
            "docker", "exec", container, "sh", "-lc",
            "pkill -TERM -f '[C]mdTlmServer' || true; pkill -TERM -f 'puma.*\\[cosmos\\]' || true",
        ],
        text=True, capture_output=True, check=False,
    )
    deadline = time.monotonic() + min(float(config.timeout_seconds), 10.0)
    while time.monotonic() < deadline and _server_pids(container):
        time.sleep(0.25)
    after_stop = _server_pids(container)
    if after_stop:
        return {
            "passed": False, "container": container, "before": before,
            "stop_returncode": stop.returncode, "stop_stderr": stop.stderr.strip(),
            "after_stop": after_stop, "reason": "cmdtlmserver_did_not_exit",
        }
    log_path = "/tmp/sc_art_cmdtlmserver.log"
    config_path = f"{config.command_server_root}/config/tools/cmd_tlm_server/cmd_tlm_server.txt"
    command = [
        "docker", "exec", "-d", "-w", config.command_server_root, container,
        "sh", "-lc",
        f"rm -f {log_path}; nohup ruby tools/CmdTlmServer --config {config_path} >{log_path} 2>&1 < /dev/null &",
    ]
    start = subprocess.run(command, text=True, capture_output=True, check=False)
    deadline = time.monotonic() + min(float(config.timeout_seconds), 10.0)
    after_start: list[str] = []
    while time.monotonic() < deadline:
        after_start = _server_pids(container)
        if _server_ready(after_start):
            break
        time.sleep(0.25)
    if _server_ready(after_start):
        time.sleep(max(float(config.settle_seconds), 1.0))
    return {
        "passed": start.returncode == 0 and _server_ready(after_start),
        "container": container, "before": before,
        "stop_returncode": stop.returncode, "stop_stderr": stop.stderr.strip(),
        "after_stop": after_stop, "start_returncode": start.returncode,
        "start_stderr": start.stderr.strip(), "after_start": after_start,
        "log_path": log_path, "log_tail": _tail_server_log(container, log_path), "command": command,
    }
