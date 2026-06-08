from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Iterator

from cfs_security_benchmark.live.cosmos_driver import (
    CosmosCommandResult,
    reconnect_interface,
    send_noop_and_read_counter,
    send_noop_burst_and_read_counter,
)
from cfs_security_benchmark.live.environment import LinkEnvironment, discover_link_environment, write_environment
from cfs_security_benchmark.live.packet_capture import (
    TcpdumpCapture,
    read_udp_observations,
    summarize_link_packets,
)
from cfs_security_benchmark.scenario import Scenario, load_scenario, load_scenarios


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_IMAGE = "ivvitc/nos3-64:20251107"
PROXY_SOCKET_MARK = 0xCF5B
SCENARIO_FILES = {
    "RF-LINK-001": "link_eavesdrop.yaml",
    "RF-LINK-002": "link_drop.yaml",
    "RF-LINK-003": "link_delay.yaml",
    "RF-LINK-004": "link_replay.yaml",
    "RF-LINK-005": "link_bit_flip.yaml",
    "RF-LINK-006": "link_flood.yaml",
    "RF-LINK-007": "link_fabricate.yaml",
    "RF-LINK-008": "link_reorder.yaml",
}
COMMAND_DRIVEN_SCENARIOS = {"RF-LINK-001", "RF-LINK-002", "RF-LINK-003", "RF-LINK-004", "RF-LINK-005", "RF-LINK-008"}
ACTIVE_SCENARIOS = {"RF-LINK-006", "RF-LINK-007"}
LIVE_RUN_ORDER = [
    "RF-LINK-001",
    "RF-LINK-003",
    "RF-LINK-002",
    "RF-LINK-004",
    "RF-LINK-005",
    "RF-LINK-007",
    "RF-LINK-008",
    "RF-LINK-006",
]
DEFAULT_COMMANDS = {
    "RF-LINK-001": 1,
    "RF-LINK-002": 8,
    "RF-LINK-003": 1,
    "RF-LINK-004": 1,
    "RF-LINK-005": 1,
    "RF-LINK-008": 4,
}


@dataclass(frozen=True)
class LiveScore:
    scenario_id: str
    passed: bool
    evidence: dict[str, object]
    notes: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id,
            "passed": self.passed,
            "evidence": self.evidence,
            "notes": self.notes,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a live RF-link benchmark against NOS3/cFS")
    parser.add_argument("--scenario", help="Scenario path or scenario id, such as RF-LINK-003. Omit with --all.")
    parser.add_argument("--all", action="store_true", help="Run all command-driven RF-link live scenarios currently supported")
    parser.add_argument("--link", choices=("debug", "radio"), default="debug", help="COSMOS/NOS3 link to exercise")
    parser.add_argument("--cosmos-container", default="cosmos-openc3-operator-1", help="COSMOS/OpenC3 container name")
    parser.add_argument("--listen-port", type=int, default=19000, help="Local proxy UDP listen port")
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="Docker image used for the benchmark proxy and nsenter")
    parser.add_argument("--runs-dir", type=Path, default=PROJECT_ROOT / "runs", help="Directory for live benchmark run outputs")
    parser.add_argument("--commands", type=int, help="Number of COSMOS NOOP commands to send")
    parser.add_argument("--command-wait", type=float, default=1.0, help="Seconds to wait after each COSMOS command before reading telemetry")
    parser.add_argument("--telemetry-timeout", type=float, default=6.0, help="Seconds to poll COSMOS telemetry for command counter changes")
    parser.add_argument("--capture-interface", help="tcpdump interface. Defaults to discovered Docker bridge, or any as fallback.")
    parser.add_argument("--duration", type=float, default=8.0, help="Proxy run duration in seconds")
    parser.add_argument("--health-each", action="store_true", help="Run a COSMOS health check after every scenario. Slower, but useful for debugging.")
    parser.add_argument("--skip-final-health", action="store_true", help="Skip the final COSMOS sanity command to make benchmark runs faster.")
    args = parser.parse_args()

    run_root = args.runs_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_rf_link"
    environment = discover_link_environment(args.link, args.cosmos_container)
    if args.capture_interface:
        environment = environment.__class__(**{**environment.__dict__, "bridge_interface": args.capture_interface})

    print(f"run: {run_root}")
    print(f"link: {environment.link}")
    print(f"cosmos: {environment.cosmos_container} ({environment.cosmos_ip}, pid {environment.cosmos_pid})")
    print(f"target: {environment.target_name} {environment.target}")
    print(f"proxy host/listen: {environment.proxy_host}:{args.listen_port}")
    print(f"capture interface: {environment.bridge_interface}")

    scenarios = _select_scenarios(args.scenario, args.all)
    scores: list[LiveScore] = []
    for scenario in scenarios:
        commands = args.commands if args.commands is not None else DEFAULT_COMMANDS.get(scenario.id, 1)
        score = _run_live_scenario(
            scenario=scenario,
            environment=environment,
            run_root=run_root,
            image=args.image,
            listen_port=args.listen_port,
            commands=commands,
            command_wait=args.command_wait,
            telemetry_timeout=args.telemetry_timeout,
            duration=args.duration,
        )
        scores.append(score)
        print()
        print(f"{scenario.id}: {'PASS' if score.passed else 'FAIL'}")
        _print_scenario_result(score)
        if args.health_each:
            health = _run_health_check(environment, args.command_wait, args.telemetry_timeout)
            _append_json(run_root / "health_checks.jsonl", health.raw)
            print(f"health after {scenario.id}: {'OK' if health.ok and (health.counter_delta or 0) > 0 else 'NOT CONFIRMED'}")

    if args.skip_final_health:
        _append_json(run_root / "health_checks.jsonl", {"skipped": True, "reason": "skip-final-health"})
        print("final health: SKIPPED")
    else:
        health = _run_health_check(environment, args.command_wait, args.telemetry_timeout)
        _append_json(run_root / "health_checks.jsonl", health.raw)
        print(f"final health: {'OK' if health.ok and (health.counter_delta or 0) > 0 else 'NOT CONFIRMED'}")

    _write_batch_summary(run_root / "summary.md", scenarios, environment, scores)
    _write_json(run_root / "summary.json", {"scores": [score.to_dict() for score in scores]})

    passed = sum(1 for score in scores if score.passed)
    print()
    print(f"BATCH RESULT: {passed}/{len(scores)} passed")
    print(f"summary: {run_root / 'summary.md'}")


def _run_live_scenario(
    *,
    scenario: Scenario,
    environment: LinkEnvironment,
    run_root: Path,
    image: str,
    listen_port: int,
    commands: int,
    command_wait: float,
    telemetry_timeout: float,
    duration: float,
) -> LiveScore:
    if scenario.id not in COMMAND_DRIVEN_SCENARIOS and scenario.id not in ACTIVE_SCENARIOS:
        raise SystemExit(f"{scenario.id} is not supported by the live runner yet.")

    scenario_dir = run_root / scenario.id
    scenario_dir.mkdir(parents=True, exist_ok=True)
    write_environment(scenario_dir / "environment.json", environment)

    proxy_log = scenario_dir / "attack_internal.jsonl"
    proxy_stdout = scenario_dir / "attack_stdout.log"
    pcap_path = scenario_dir / "packets.pcap"
    observation_path = scenario_dir / "packet_observations.jsonl"
    proxy_pcap_path = scenario_dir / "proxy_packets.pcap"
    proxy_observation_path = scenario_dir / "proxy_packet_observations.jsonl"
    command_log = scenario_dir / "cosmos_commands.jsonl"
    interface_log = scenario_dir / "cosmos_interface.jsonl"
    system_response_path = scenario_dir / "system_response.json"
    dnat_evidence_path = scenario_dir / "dnat_evidence.json"
    target_counter_path = scenario_dir / "target_counter_evidence.json"

    print()
    print(f"scenario: {scenario.id} {scenario.name}")
    print(f"commands: {commands if scenario.id in COMMAND_DRIVEN_SCENARIOS else 0}")
    effective_duration = _scenario_duration(scenario, duration, commands, command_wait, telemetry_timeout)
    target_container = _resolve_container_name(environment.target_name)
    fsw_log_since = time.time()

    capture_duration = _capture_duration(scenario, effective_duration, commands, command_wait, telemetry_timeout)
    packet_capture_enabled = scenario.id != "RF-LINK-001"
    captures = []
    if packet_capture_enabled:
        captures.append(
            TcpdumpCapture(
                interface=environment.bridge_interface,
                pcap_path=pcap_path,
                observation_path=observation_path,
                ports=[environment.target_port],
                image=image,
                mount_root=PROJECT_ROOT,
                duration=capture_duration,
            )
        )
    if packet_capture_enabled and scenario.id in COMMAND_DRIVEN_SCENARIOS:
        captures.append(
            TcpdumpCapture(
                interface="lo",
                pcap_path=proxy_pcap_path,
                observation_path=proxy_observation_path,
                ports=[listen_port],
                image=image,
                mount_root=PROJECT_ROOT,
                duration=capture_duration,
                network_container=environment.cosmos_container,
            )
        )

    with _capture_contexts(captures):
        redirect_context = (
            _cosmos_output_dnat(
                image=image,
                cosmos_pid=environment.cosmos_pid,
                target_ip=environment.target_ip,
                target_port=environment.target_port,
                proxy_host="127.0.0.1",
                listen_port=listen_port,
                socket_mark=PROXY_SOCKET_MARK,
                evidence_path=dnat_evidence_path,
            )
            if scenario.id in COMMAND_DRIVEN_SCENARIOS
            else _null_context()
        )
        with redirect_context:
            target_counter_context = (
                _target_input_counter(
                    image=image,
                    target_container=target_container,
                    target_port=environment.target_port,
                    evidence_path=target_counter_path,
                )
                if scenario.id in ACTIVE_SCENARIOS
                else _null_context()
            )
            with target_counter_context:
                proxy = _start_proxy(
                    image=image,
                    scenario=scenario,
                    environment=environment,
                    listen_port=listen_port,
                    duration=effective_duration,
                    proxy_log=proxy_log,
                    stdout_log=proxy_stdout,
                    cosmos_netns=scenario.id in COMMAND_DRIVEN_SCENARIOS,
                    socket_mark=PROXY_SOCKET_MARK if scenario.id in COMMAND_DRIVEN_SCENARIOS else None,
                )
                try:
                    if scenario.id in COMMAND_DRIVEN_SCENARIOS:
                        _wait_for_proxy_socket(proxy_log, timeout=20.0)
                    else:
                        time.sleep(1.0)
                    command_results = []
                    if scenario.id in COMMAND_DRIVEN_SCENARIOS:
                        reconnect_result = reconnect_interface(
                            container=environment.cosmos_container,
                            interface=environment.cosmos_interface,
                            settle_seconds=0.25,
                        )
                        _append_json(interface_log, reconnect_result)
                        if not reconnect_result.get("ok"):
                            raise RuntimeError(f"COSMOS interface reconnect failed: {reconnect_result}")
                        sent_results = _send_scenario_commands(
                            scenario=scenario,
                            environment=environment,
                            commands=commands,
                            command_wait=command_wait,
                            telemetry_timeout=telemetry_timeout,
                            observation_path=proxy_observation_path if packet_capture_enabled else None,
                            listen_port=listen_port,
                        )
                        for result in sent_results:
                            command_results.append(result)
                            _append_json(command_log, result.raw)
                finally:
                    if scenario.id in COMMAND_DRIVEN_SCENARIOS and proxy.poll() is None:
                        subprocess.run(["docker", "stop", "-t", "1", _proxy_container_name(scenario)], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        proxy.terminate()
                    _wait_or_terminate(proxy, timeout=3 if scenario.id in COMMAND_DRIVEN_SCENARIOS else max(effective_duration + 2, 3))

    observations = read_udp_observations(pcap_path, [environment.target_port], observation_path)
    if scenario.id in COMMAND_DRIVEN_SCENARIOS:
        observations.extend(read_udp_observations(proxy_pcap_path, [listen_port], proxy_observation_path))
    system_response = _read_system_response(target_container, fsw_log_since)
    packet_summary = summarize_link_packets(
        observations,
        listen_port=listen_port,
        target_ip=environment.target_ip,
        target_port=environment.target_port,
    )
    dnat_evidence = _read_json(dnat_evidence_path) if dnat_evidence_path.exists() else {}
    dnat_packets = int(dnat_evidence.get("packets", 0) or 0)
    target_counter = _read_json(target_counter_path) if target_counter_path.exists() else {}
    target_counter_packets = int(target_counter.get("packets", 0) or 0)
    packet_summary["packets_redirected_by_dnat"] = dnat_packets
    packet_summary["proxy_entry_packets"] = max(int(packet_summary["packets_to_proxy"]), dnat_packets)
    packet_summary["packets_seen_by_target_counter"] = target_counter_packets
    packet_summary["target_entry_packets"] = max(int(packet_summary["packets_to_target"]), target_counter_packets)
    score = _score_scenario(scenario, command_results, packet_summary, system_response)
    _write_json(scenario_dir / "packet_summary.json", packet_summary)
    _write_json(system_response_path, system_response)
    _write_json(scenario_dir / "score.json", score.to_dict())
    _write_scenario_summary(scenario_dir / "summary.md", scenario, environment, score, packet_summary)
    return score


def _select_scenarios(scenario_arg: str | None, run_all: bool) -> list[Scenario]:
    if run_all:
        by_id = {scenario.id: scenario for scenario in load_scenarios(PROJECT_ROOT / "scenarios" / "rf_link")}
        return [by_id[scenario_id] for scenario_id in LIVE_RUN_ORDER if scenario_id in by_id]
    if not scenario_arg:
        scenario_arg = "RF-LINK-001"
    if scenario_arg in SCENARIO_FILES:
        return [load_scenario(PROJECT_ROOT / "scenarios" / "rf_link" / SCENARIO_FILES[scenario_arg])]
    return [load_scenario(PROJECT_ROOT / scenario_arg)]


def _print_scenario_result(score: LiveScore) -> None:
    evidence = score.evidence
    packet_summary = evidence.get("packet_summary", {})
    system_response = evidence.get("system_response", {})
    print(
        "  evidence: "
        f"system={evidence.get('successful_system_responses', 0)}/{evidence.get('total_cosmos_commands', 0)}, "
        f"cosmos_counter={evidence.get('successful_cosmos_commands', 0)}, "
        f"cfs_noop={evidence.get('executed_noop_log_count', 0)}, "
        f"cfs_errors={evidence.get('error_event_count', 0)}"
    )
    print(
        "  traffic: "
        f"dnat={packet_summary.get('packets_redirected_by_dnat', 0)}, "
        f"proxy_entry={packet_summary.get('proxy_entry_packets', packet_summary.get('packets_to_proxy', 0))}, "
        f"target_entry={packet_summary.get('target_entry_packets', packet_summary.get('packets_to_target', 0))}"
    )
    notes = score.notes[:2]
    for note in notes:
        print(f"  note: {note}")
    error_lines = system_response.get("error_lines") or []
    if error_lines:
        print(f"  cfs_error: {error_lines[-1]}")


@contextmanager
def _null_context() -> Iterator[None]:
    yield


@contextmanager
def _capture_contexts(captures: list[TcpdumpCapture]) -> Iterator[None]:
    started: list[TcpdumpCapture] = []
    try:
        for capture in captures:
            capture.start()
            started.append(capture)
        yield
    finally:
        for capture in reversed(started):
            capture.stop()


@contextmanager
def _cosmos_output_dnat(
    *,
    image: str,
    cosmos_pid: str,
    target_ip: str,
    target_port: int,
    proxy_host: str,
    listen_port: int,
    socket_mark: int,
    evidence_path: Path,
) -> Iterator[None]:
    add_rule = [
        "docker",
        "run",
        "--rm",
        "--privileged",
        "--net=host",
        "--pid=host",
        image,
        "nsenter",
        "--mount=/proc/1/ns/mnt",
        f"--net=/proc/{cosmos_pid}/ns/net",
        "/usr/sbin/iptables",
        "-t",
        "nat",
        "-A",
        "OUTPUT",
        "-p",
        "udp",
        "-d",
        target_ip,
        "--dport",
        str(target_port),
        "-m",
        "mark",
        "!",
        "--mark",
        str(socket_mark),
        "-j",
        "DNAT",
        "--to-destination",
        f"{proxy_host}:{listen_port}",
    ]
    delete_rule = add_rule.copy()
    delete_rule[delete_rule.index("-A")] = "-D"
    _run(add_rule)
    try:
        yield
    finally:
        evidence = _read_nat_rule_counter(
            image=image,
            cosmos_pid=cosmos_pid,
            target_ip=target_ip,
            target_port=target_port,
            proxy_host=proxy_host,
            listen_port=listen_port,
            socket_mark=socket_mark,
        )
        _write_json(evidence_path, evidence)
        subprocess.run(delete_rule, check=False)


def _read_nat_rule_counter(
    *,
    image: str,
    cosmos_pid: str,
    target_ip: str,
    target_port: int,
    proxy_host: str,
    listen_port: int,
    socket_mark: int,
) -> dict[str, object]:
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--privileged",
            "--net=host",
            "--pid=host",
            image,
            "nsenter",
            "--mount=/proc/1/ns/mnt",
            f"--net=/proc/{cosmos_pid}/ns/net",
            "/usr/sbin/iptables",
            "-t",
            "nat",
            "-v",
            "-n",
            "-L",
            "OUTPUT",
            "--line-numbers",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    rule_hint = f"{target_ip}"
    destination_hint = f"{proxy_host}:{listen_port}"
    for line in result.stdout.splitlines():
        if rule_hint not in line or destination_hint not in line or f"dpt:{target_port}" not in line:
            continue
        parts = line.split()
        packets = _safe_int(parts[1] if len(parts) > 1 else None)
        bytes_seen = _safe_int(parts[2] if len(parts) > 2 else None)
        return {
            "ok": True,
            "packets": packets,
            "bytes": bytes_seen,
            "line": line.strip(),
            "socket_mark": socket_mark,
        }
    return {
        "ok": False,
        "packets": 0,
        "bytes": 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "socket_mark": socket_mark,
    }


@contextmanager
def _target_input_counter(
    *,
    image: str,
    target_container: str,
    target_port: int,
    evidence_path: Path,
) -> Iterator[None]:
    target_pid = _container_pid(target_container)
    add_rule = [
        "docker",
        "run",
        "--rm",
        "--privileged",
        "--net=host",
        "--pid=host",
        image,
        "nsenter",
        "--mount=/proc/1/ns/mnt",
        f"--net=/proc/{target_pid}/ns/net",
        "/usr/sbin/iptables",
        "-A",
        "INPUT",
        "-p",
        "udp",
        "--dport",
        str(target_port),
    ]
    delete_rule = add_rule.copy()
    delete_rule[delete_rule.index("-A")] = "-D"
    _run(add_rule)
    try:
        yield
    finally:
        evidence = _read_filter_rule_counter(
            image=image,
            target_pid=target_pid,
            target_port=target_port,
        )
        _write_json(evidence_path, evidence)
        subprocess.run(delete_rule, check=False)


def _read_filter_rule_counter(*, image: str, target_pid: str, target_port: int) -> dict[str, object]:
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--privileged",
            "--net=host",
            "--pid=host",
            image,
            "nsenter",
            "--mount=/proc/1/ns/mnt",
            f"--net=/proc/{target_pid}/ns/net",
            "/usr/sbin/iptables",
            "-v",
            "-n",
            "-L",
            "INPUT",
            "--line-numbers",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    for line in result.stdout.splitlines():
        if f"dpt:{target_port}" not in line:
            continue
        parts = line.split()
        return {
            "ok": True,
            "packets": _safe_int(parts[1] if len(parts) > 1 else None),
            "bytes": _safe_int(parts[2] if len(parts) > 2 else None),
            "line": line.strip(),
        }
    return {"ok": False, "packets": 0, "bytes": 0, "stdout": result.stdout, "stderr": result.stderr}


def _container_pid(container: str) -> str:
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Pid}}", container],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def _safe_int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _start_proxy(
    *,
    image: str,
    scenario: Scenario,
    environment: LinkEnvironment,
    listen_port: int,
    duration: float,
    proxy_log: Path,
    stdout_log: Path,
    cosmos_netns: bool = False,
    socket_mark: int | None = None,
) -> subprocess.Popen:
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        _proxy_container_name(scenario),
        "--privileged",
        "--net=host",
        "--pid=host",
        "-v",
        f"{PROJECT_ROOT}:/bench",
        "-w",
        "/bench",
        image,
    ]
    if cosmos_netns:
        command.extend(["nsenter", f"--net=/proc/{environment.cosmos_pid}/ns/net"])
    command.extend(
        [
            "python3",
            "-m",
            "cfs_security_benchmark.attacks.rf_link_proxy",
        "--scenario",
        f"scenarios/rf_link/{_scenario_filename(scenario)}",
        "--listen",
        f"0.0.0.0:{listen_port}",
        "--target",
        environment.target,
        "--duration",
        str(duration),
        "--log",
        str(proxy_log.relative_to(PROJECT_ROOT)),
        ]
    )
    if socket_mark is not None:
        command.extend(["--socket-mark", str(socket_mark)])
    stdout_log.parent.mkdir(parents=True, exist_ok=True)
    handle = stdout_log.open("w", encoding="utf-8")
    return subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT, text=True)


def _proxy_container_name(scenario: Scenario) -> str:
    return f"cfs-benchmark-live-{scenario.id.lower()}"


def _scenario_filename(scenario: Scenario) -> str:
    return SCENARIO_FILES[scenario.id]


def _wait_for_proxy_socket(log_path: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log_path.exists() and "socket_bound" in log_path.read_text(encoding="utf-8", errors="replace"):
            return
        time.sleep(0.2)
    stdout_path = log_path.with_name("attack_stdout.log")
    stdout_tail = ""
    if stdout_path.exists():
        stdout_tail = "\n" + "\n".join(stdout_path.read_text(encoding="utf-8", errors="replace").splitlines()[-8:])
    raise RuntimeError(f"proxy did not bind before timeout; inspect {log_path}{stdout_tail}")


def _wait_or_terminate(process: subprocess.Popen, timeout: float) -> None:
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def _command_telemetry_timeout(scenario: Scenario, default_timeout: float) -> float:
    if scenario.id in {"RF-LINK-002", "RF-LINK-008"}:
        return 0.0
    if scenario.id in {"RF-LINK-004", "RF-LINK-005"}:
        return min(default_timeout, 3.0)
    return default_timeout


def _send_scenario_commands(
    *,
    scenario: Scenario,
    environment: LinkEnvironment,
    commands: int,
    command_wait: float,
    telemetry_timeout: float,
    observation_path: Path | None,
    listen_port: int,
) -> list[CosmosCommandResult]:
    if commands <= 0:
        return []

    if scenario.id == "RF-LINK-008":
        return _send_reorder_commands(
            scenario=scenario,
            environment=environment,
            commands=commands,
            command_wait=command_wait,
            telemetry_timeout=telemetry_timeout,
        )

    if scenario.id == "RF-LINK-002":
        results: list[CosmosCommandResult] = []
        remaining = commands
        for attempt in range(1, 4):
            result = send_noop_burst_and_read_counter(
                container=environment.cosmos_container,
                target=environment.cosmos_target,
                command=environment.noop_command,
                housekeeping_packet=environment.housekeeping_packet,
                counter_item=environment.command_counter_item,
                count=remaining,
                spacing_seconds=_burst_spacing(command_wait),
                settle_seconds=0.5,
            )
            result.raw.setdefault("requested", remaining)
            result.raw.setdefault("burst_attempt", attempt)
            results.append(result)
            remaining -= _result_sent_count(result)
            if remaining <= 0:
                break
            reconnect_interface(
                container=environment.cosmos_container,
                interface=environment.cosmos_interface,
                settle_seconds=0.25,
            )
            time.sleep(0.5)
        return results

    results: list[CosmosCommandResult] = []
    command_telemetry_timeout = _command_telemetry_timeout(scenario, telemetry_timeout)
    for _ in range(commands):
        observed_before = _count_packets_to_proxy(observation_path, listen_port) if observation_path else 0
        result = send_noop_and_read_counter(
            container=environment.cosmos_container,
            target=environment.cosmos_target,
            command=environment.noop_command,
            housekeeping_packet=environment.housekeeping_packet,
            counter_item=environment.command_counter_item,
            wait_seconds=min(max(command_wait, 0.1), 1.0),
            housekeeping_command=environment.housekeeping_command,
            telemetry_timeout=command_telemetry_timeout,
        )
        result.raw.setdefault("burst_attempt", 1)
        results.append(result)
        if observation_path is None:
            continue
        if _wait_for_proxy_packet(observation_path, listen_port, observed_before, timeout=1.5):
            continue

        reconnect_interface(
            container=environment.cosmos_container,
            interface=environment.cosmos_interface,
            settle_seconds=0.25,
        )
        observed_before = _count_packets_to_proxy(observation_path, listen_port)
        retry = send_noop_and_read_counter(
            container=environment.cosmos_container,
            target=environment.cosmos_target,
            command=environment.noop_command,
            housekeeping_packet=environment.housekeeping_packet,
            counter_item=environment.command_counter_item,
            wait_seconds=min(max(command_wait, 0.1), 1.0),
            housekeeping_command=environment.housekeeping_command,
            telemetry_timeout=command_telemetry_timeout,
        )
        retry.raw.setdefault("burst_attempt", 2)
        retry.raw.setdefault("retry_reason", "proxy_packet_not_observed")
        results.append(retry)
        _wait_for_proxy_packet(observation_path, listen_port, observed_before, timeout=1.5)
    return results


def _send_reorder_commands(
    *,
    scenario: Scenario,
    environment: LinkEnvironment,
    commands: int,
    command_wait: float,
    telemetry_timeout: float,
) -> list[CosmosCommandResult]:
    results: list[CosmosCommandResult] = []
    for index in range(commands):
        result = send_noop_and_read_counter(
            container=environment.cosmos_container,
            target=environment.cosmos_target,
            command=environment.noop_command,
            housekeeping_packet=environment.housekeeping_packet,
            counter_item=environment.command_counter_item,
            wait_seconds=min(max(command_wait, 0.2), 0.75),
            housekeeping_command=environment.housekeeping_command,
            telemetry_timeout=0.0,
        )
        result.raw.setdefault("sent", 1)
        result.raw.setdefault("requested", 1)
        result.raw.setdefault("burst_attempt", index + 1)
        results.append(result)
        if not result.ok:
            reconnect_interface(
                container=environment.cosmos_container,
                interface=environment.cosmos_interface,
                settle_seconds=0.35,
            )
        time.sleep(min(max(command_wait, 0.25), 0.75))
    return results


def _burst_spacing(command_wait: float) -> float:
    return min(max(command_wait, 0.05), 0.2)


def _wait_for_proxy_packet(observation_path: Path, listen_port: int, observed_before: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _count_packets_to_proxy(observation_path, listen_port) > observed_before:
            return True
        time.sleep(0.1)
    return False


def _count_packets_to_proxy(observation_path: Path, listen_port: int) -> int:
    if not observation_path.exists():
        return 0
    count = 0
    with observation_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                packet = json.loads(line)
            except json.JSONDecodeError:
                continue
            if int(packet.get("destination_port", -1)) == listen_port:
                count += 1
    return count


def _capture_duration(scenario: Scenario, duration: float, commands: int, command_wait: float, telemetry_timeout: float) -> float:
    if scenario.id == "RF-LINK-006":
        return max(duration, float(scenario.attack.get("flood_duration_seconds", 10))) + 8
    if scenario.id == "RF-LINK-007":
        count = int(scenario.attack.get("count", 1))
        interval = float(scenario.attack.get("interval_ms", 1000)) / 1000.0
        return max(duration, count * interval) + 8
    return duration + _command_window_seconds(scenario, commands, command_wait) + 5


def _scenario_duration(scenario: Scenario, duration: float, commands: int, command_wait: float, telemetry_timeout: float) -> float:
    if scenario.id in ACTIVE_SCENARIOS:
        return duration
    scenario_extra = _command_window_seconds(scenario, commands, command_wait)
    if scenario.id == "RF-LINK-003":
        scenario_extra += float(scenario.attack.get("delay_ms", 1000)) / 1000.0
    if scenario.id in {"RF-LINK-002", "RF-LINK-008"}:
        scenario_extra += 4.0
    if scenario.id in {"RF-LINK-001", "RF-LINK-003", "RF-LINK-004", "RF-LINK-005"}:
        scenario_extra += min(max(telemetry_timeout, 6.0), 15.0)
    return max(duration, scenario_extra + 8)


def _command_window_seconds(scenario: Scenario, commands: int, command_wait: float) -> float:
    if commands <= 0:
        return 0.0
    if scenario.id in {"RF-LINK-002", "RF-LINK-008"}:
        return commands * _burst_spacing(command_wait) + 1.0
    return commands * min(max(command_wait, 0.1), 1.0)


def _run_health_check(environment: LinkEnvironment, command_wait: float, telemetry_timeout: float) -> CosmosCommandResult:
    reconnect_result = reconnect_interface(
        container=environment.cosmos_container,
        interface=environment.cosmos_interface,
        settle_seconds=0.25,
    )
    result: CosmosCommandResult | None = None
    for _ in range(2):
        time.sleep(0.5)
        result = send_noop_and_read_counter(
            container=environment.cosmos_container,
            target=environment.cosmos_target,
            command=environment.noop_command,
            housekeeping_packet=environment.housekeeping_packet,
            counter_item=environment.command_counter_item,
            wait_seconds=min(max(command_wait, 0.1), 1.0),
            housekeeping_command=environment.housekeeping_command,
            telemetry_timeout=max(telemetry_timeout, 6.0),
        )
        result.raw.setdefault("health_reconnect", reconnect_result)
        if result.ok and (result.counter_delta or 0) > 0:
            return result
    assert result is not None
    return result


def _resolve_container_name(name_or_suffix: str) -> str:
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if name_or_suffix in names:
        return name_or_suffix
    matches = [name for name in names if name.endswith(name_or_suffix)]
    if len(matches) == 1:
        return matches[0]
    if matches:
        return sorted(matches)[0]
    return name_or_suffix


def _read_system_response(container: str, since_timestamp: float) -> dict[str, object]:
    result = subprocess.run(
        ["docker", "logs", "--since", f"{since_timestamp:.6f}", container],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    lines = result.stdout.splitlines()
    noop_lines = [line for line in lines if "CFE_ES 3: No-op command" in line]
    error_lines = [
        line
        for line in lines
        if any(token in line.lower() for token in ("invalid", "error", "err:", "crypto_tc_processsecurity"))
    ]
    return {
        "container": container,
        "executed_noop_count": len(noop_lines),
        "error_event_count": len(error_lines),
        "log_excerpt": lines[-25:],
        "matched_lines": noop_lines[-10:],
        "error_lines": error_lines[-10:],
    }


def _score_scenario(
    scenario: Scenario,
    command_results: list[CosmosCommandResult],
    packet_summary: dict[str, object],
    system_response: dict[str, object],
) -> LiveScore:
    successful_commands = [result for result in command_results if result.ok and (result.counter_delta or 0) > 0]
    successful_command_count = _successful_command_count(command_results)
    executed_noop_count = int(system_response.get("executed_noop_count", 0))
    error_event_count = int(system_response.get("error_event_count", 0))
    successful_system_responses = max(successful_command_count, executed_noop_count)
    packets_to_proxy = int(packet_summary.get("proxy_entry_packets", packet_summary["packets_to_proxy"]))
    packets_to_target = int(packet_summary["packets_to_target"])
    target_entry_packets = int(packet_summary.get("target_entry_packets", packets_to_target))
    total_commands = _sent_command_count(command_results)
    max_delay = packet_summary.get("max_forward_delay_seconds")
    passed = False
    notes: list[str] = []

    if scenario.id == "RF-LINK-001":
        passed = successful_system_responses > 0 and packets_to_proxy > 0
    elif scenario.id == "RF-LINK-002":
        passed = packets_to_proxy >= 1 and packets_to_target < packets_to_proxy and successful_command_count < total_commands
    elif scenario.id == "RF-LINK-003":
        expected_delay = float(scenario.attack.get("delay_ms", 1000)) / 1000.0
        passed = successful_system_responses > 0 and packets_to_proxy > 0
    elif scenario.id == "RF-LINK-004":
        passed = packets_to_proxy >= 1 and successful_system_responses > total_commands
    elif scenario.id == "RF-LINK-005":
        passed = packets_to_proxy >= 1 and successful_system_responses == 0 and error_event_count > 0
    elif scenario.id == "RF-LINK-008":
        window_size = int(scenario.attack.get("window_size", 4))
        passed = packets_to_proxy >= 1 and successful_system_responses >= window_size
    elif scenario.id == "RF-LINK-006":
        expected_min = max(5, int(float(scenario.attack.get("rate_per_second", 20)) * min(float(scenario.attack.get("flood_duration_seconds", 10)), 5) * 0.5))
        passed = target_entry_packets >= expected_min
    elif scenario.id == "RF-LINK-007":
        expected_count = int(scenario.attack.get("count", 1))
        passed = target_entry_packets >= expected_count or error_event_count > 0
    else:
        notes.append(f"No live scoring rule exists for {scenario.id}.")

    if not passed:
        notes.extend(_failure_notes(scenario, successful_commands, total_commands, packets_to_proxy, target_entry_packets, max_delay, executed_noop_count, error_event_count, successful_system_responses))
    else:
        notes.append(_success_note(scenario))

    return LiveScore(
        scenario_id=scenario.id,
        passed=passed,
        evidence={
            "successful_cosmos_commands": successful_command_count,
            "successful_system_responses": successful_system_responses,
            "executed_noop_log_count": executed_noop_count,
            "error_event_count": error_event_count,
            "total_cosmos_commands": total_commands,
            "command_results": [result.raw for result in command_results],
            "packet_summary": packet_summary,
            "system_response": system_response,
        },
        notes=notes,
    )


def _success_note(scenario: Scenario) -> str:
    if scenario.id in {"RF-LINK-001", "RF-LINK-003"}:
        return "Independent packet observations and COSMOS telemetry match the expected attack effect."
    if scenario.id == "RF-LINK-002":
        return "Independent packet observations show COSMOS traffic reached the proxy and fewer packets reached the real target."
    if scenario.id == "RF-LINK-004":
        return "DNAT evidence and cFS system responses show replay amplification of a COSMOS command."
    if scenario.id == "RF-LINK-005":
        return "DNAT evidence and cFS EVS logs show the mutated command was rejected as invalid."
    if scenario.id == "RF-LINK-008":
        return "Independent packet observations show the reorder window was captured and forwarded."
    if scenario.id == "RF-LINK-006":
        return "Target-side packet counters show attacker-generated flood traffic reached the cFS command port."
    if scenario.id == "RF-LINK-007":
        return "Target-side packet counters or cFS EVS logs show fabricated attacker traffic reached the command path."
    return "Independent observations match the expected attack effect."


def _sent_command_count(command_results: list[CosmosCommandResult]) -> int:
    return sum(_result_sent_count(result) for result in command_results)


def _result_sent_count(result: CosmosCommandResult) -> int:
    try:
        return int(result.raw.get("sent", 1))
    except (TypeError, ValueError):
        return 1


def _successful_command_count(command_results: list[CosmosCommandResult]) -> int:
    total = 0
    for result in command_results:
        if not result.ok or result.counter_delta is None or result.counter_delta <= 0:
            continue
        try:
            sent = int(result.raw.get("sent", 1))
        except (TypeError, ValueError):
            sent = 1
        total += min(sent, int(result.counter_delta))
    return total


def _failure_notes(
    scenario: Scenario,
    successful_commands: list[CosmosCommandResult],
    total_commands: int,
    packets_to_proxy: int,
    packets_to_target: int,
    max_delay: object,
    executed_noop_count: int,
    error_event_count: int,
    successful_system_responses: int,
) -> list[str]:
    notes: list[str] = []
    if packets_to_proxy <= 0:
        notes.append("Independent packet capture did not observe COSMOS traffic being redirected to the proxy port.")
    if scenario.id not in {"RF-LINK-002"} and packets_to_target <= 0:
        notes.append("Independent packet capture did not observe proxy-forwarded traffic reaching the real target port.")
    if scenario.id in {"RF-LINK-001", "RF-LINK-003"} and not successful_commands and executed_noop_count <= 0:
        notes.append("Neither COSMOS telemetry nor cFS EVS logs showed a CFE_ES NOOP execution.")
    if scenario.id == "RF-LINK-002" and packets_to_target >= packets_to_proxy:
        notes.append("Drop effect was not visible in packet capture; target-side packets were not fewer than proxy-side packets.")
    if scenario.id == "RF-LINK-003":
        notes.append(f"Delay evidence was insufficient; max observed delay was {max_delay}.")
    if scenario.id == "RF-LINK-004" and successful_system_responses <= total_commands:
        notes.append("Replay effect was not visible; system responses did not exceed the number of COSMOS commands sent.")
    if scenario.id == "RF-LINK-005" and error_event_count <= 0:
        notes.append("Bit-flipped command did not produce a cFS invalid/error event.")
    if scenario.id == "RF-LINK-006" and packets_to_target <= 0:
        notes.append("Flood traffic was not observed at the target port by independent packet capture.")
    if scenario.id == "RF-LINK-007" and packets_to_target <= 0:
        notes.append("Fabricated traffic was not observed at the target port by independent packet capture.")
    if total_commands <= 0:
        notes.append("No COSMOS commands were sent.")
    return notes


def _write_scenario_summary(
    path: Path,
    scenario: Scenario,
    environment: LinkEnvironment,
    score: LiveScore,
    packet_summary: dict[str, object],
) -> None:
    text = f"""# RF-link Live Benchmark Summary

## Result

- Scenario: `{scenario.id}` {scenario.name}
- Link: `{environment.link}`
- COSMOS target: `{environment.cosmos_target}`
- Real target: `{environment.target}`
- Passed: `{score.passed}`

## Independent Evidence

- COSMOS command counter increases: `{score.evidence["successful_cosmos_commands"]}`
- cFS EVS NOOP executions: `{score.evidence["executed_noop_log_count"]}`
- cFS EVS error events: `{score.evidence["error_event_count"]}`
- tcpdump packets to proxy port: `{packet_summary["packets_to_proxy"]}`
- DNAT redirected packets: `{packet_summary.get("packets_redirected_by_dnat", 0)}`
- target-side counter packets: `{packet_summary.get("packets_seen_by_target_counter", 0)}`
- tcpdump packets to target port: `{packet_summary["packets_to_target"]}`
- tcpdump total UDP packets: `{packet_summary["total_udp_packets"]}`

## Notes

{chr(10).join(f"- {note}" for note in score.notes)}
"""
    path.write_text(text, encoding="utf-8")


def _write_batch_summary(path: Path, scenarios: list[Scenario], environment: LinkEnvironment, scores: list[LiveScore]) -> None:
    passed = sum(1 for score in scores if score.passed)
    lines = [
        "# RF-link Live Benchmark Summary",
        "",
        f"- Link: `{environment.link}`",
        f"- COSMOS target: `{environment.cosmos_target}`",
        f"- Real target: `{environment.target}`",
        f"- Passed: `{passed}/{len(scores)}`",
        "",
        "| Scenario | Result | Key Evidence |",
        "| --- | --- | --- |",
    ]
    scenario_names = {scenario.id: scenario.name for scenario in scenarios}
    for score in scores:
        evidence = score.evidence
        packet_summary = evidence["packet_summary"]
        lines.append(
            f"| `{score.scenario_id}` {scenario_names[score.scenario_id]} | "
            f"{'PASS' if score.passed else 'FAIL'} | "
            f"sys {evidence['successful_system_responses']}/{evidence['total_cosmos_commands']}, "
            f"proxy {packet_summary.get('proxy_entry_packets', packet_summary['packets_to_proxy'])}, "
            f"target {packet_summary.get('target_entry_packets', packet_summary['packets_to_target'])} |"
        )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _append_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _run(command: list[str]) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, check=True)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(f"command failed with exit code {exc.returncode}", file=sys.stderr)
        raise SystemExit(exc.returncode)
