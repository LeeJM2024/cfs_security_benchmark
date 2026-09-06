from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from collections import defaultdict, deque
from datetime import datetime
import json
from pathlib import Path
import subprocess
import sys
import socket
import time
from typing import Iterator

from benchmark_engine.nos3.cosmos_driver import (
    CosmosCommandResult,
    send_noop_and_read_counter,
    send_noop_burst_and_read_counter,
)
from benchmark_engine.nos3.environment import (
    CryptographicBoundaryEnvironment,
    CryptographicBoundaryPath,
    LinkEnvironment,
    discover_cryptographic_boundary_environment,
    discover_cryptographic_boundary_environment_host_only,
    discover_link_environment,
    write_environment,
)
from benchmark_engine.nos3.debug_downlink import DebugDownlinkSession, send_debug_housekeeping
from benchmark_engine.nos3.radio_downlink import RadioDownlinkSession, send_radio_housekeeping
from benchmark_engine.nos3.packet_capture import (
    TcpdumpCapture,
    read_udp_observations,
    summarize_link_packets,
)
from benchmark_engine.core.scenario import Scenario, load_scenario, load_scenarios
from benchmark_engine.rf_link.threat_models import THREAT_MODEL_IDS, ThreatModel, load_threat_model
from benchmark_engine.rf_link.bridge_fault import (
    ProtectedBridgeCiphertextMutation,
    ProtectedBridgeDrop,
    ProtectedMediumFlood,
    ProtectedMediumDelay,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_IMAGE = "ivvitc/nos3-64:20251107"
PROXY_SOCKET_MARK = 0xCF5B
TPROXY_PACKET_MARK = 0x1
TPROXY_ROUTING_TABLE = 100
TPROXY_RULE_PRIORITY = 100
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
    "RF-LINK-002": 1,
    "RF-LINK-003": 1,
    "RF-LINK-004": 1,
    "RF-LINK-005": 1,
    "RF-LINK-008": 4,
}
DEFAULT_DOWNLINK_STIMULI = {
    "RF-LINK-001": 3,
    "RF-LINK-002": 1,
    "RF-LINK-003": 3,
    "RF-LINK-004": 4,
    "RF-LINK-005": 3,
    "RF-LINK-006": 4,
    "RF-LINK-007": 4,
    "RF-LINK-008": 4,
}


@dataclass(frozen=True)
class LiveScore:
    scenario_id: str
    passed: bool
    evidence: dict[str, object]
    notes: list[str]
    direction: str = "uplink"
    threat_model: str = "trusted-domain"
    attack_effect: str = "not_assessed"

    def to_dict(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id,
            "direction": self.direction,
            "passed": self.passed,
            "threat_model": self.threat_model,
            "attack_effect": self.attack_effect,
            "evidence": self.evidence,
            "notes": self.notes,
        }


@dataclass
class UplinkInterceptionSession:
    """Owns one transparent command-path interception flow for a run."""

    owner: str
    link: str
    target: str
    interface: str
    listen_port: int
    ready: bool = False
    preflight: dict[str, object] | None = None
    cleanup_warning: str | None = None

    def snapshot(self) -> dict[str, object]:
        return {
            "owner": self.owner,
            "link": self.link,
            "target": self.target,
            "interface": self.interface,
            "listen_port": self.listen_port,
            "uplink_interception_ready": self.ready,
            "preflight": self.preflight,
            "cleanup_warning": self.cleanup_warning,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a live RF-link benchmark against NOS3/cFS")
    parser.add_argument("--scenario", help="Scenario path or scenario id, such as RF-LINK-003. Omit with --all.")
    parser.add_argument("--all", action="store_true", help="Run all RF-link live scenarios currently supported")
    parser.add_argument(
        "--all-threat-models",
        action="store_true",
        help="Run the benchmark-wide sequence: trusted-domain DEBUG and RADIO RF001-RF008, then cryptographic-boundary RADIO RF001-RF006. RF007/RF008 are left for the separately armed MITM session.",
    )
    parser.add_argument("--direction", choices=("uplink", "downlink", "both"), default="both", help="Link direction case to execute")
    parser.add_argument("--link", choices=("debug", "radio"), default="debug", help="COSMOS/NOS3 link to exercise")
    parser.add_argument(
        "--threat-model",
        choices=THREAT_MODEL_IDS,
        default="trusted-domain",
        help="Attacker placement: trusted-domain uses existing COSMOS-side UDP interception; cryptographic-boundary observes the protected CryptoLib-radio-sim TCP segment.",
    )
    parser.add_argument("--cosmos-container", default="cosmos-openc3-operator-1", help="COSMOS/OpenC3 container name")
    parser.add_argument("--listen-port", type=int, default=19000, help="Local proxy UDP listen port")
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="Docker image used for the benchmark proxy and nsenter")
    parser.add_argument("--runs-dir", type=Path, default=PROJECT_ROOT / "artifacts" / "runs", help="Directory for live benchmark run outputs")
    parser.add_argument("--commands", type=int, help="Number of uplink NOOP commands or downlink telemetry requests to send")
    parser.add_argument("--command-wait", type=float, default=1.0, help="Seconds to wait after each COSMOS command before reading telemetry")
    parser.add_argument("--telemetry-timeout", type=float, default=6.0, help="Seconds to poll COSMOS telemetry for command counter changes")
    parser.add_argument("--capture-interface", help="tcpdump interface. Defaults to discovered Docker bridge, or any as fallback.")
    parser.add_argument("--duration", type=float, default=8.0, help="Proxy run duration in seconds")
    parser.add_argument("--health-each", action="store_true", help="Run a COSMOS health check after every scenario. Slower, but useful for debugging.")
    parser.add_argument("--skip-final-health", action="store_true", help="Skip the final COSMOS sanity command to make benchmark runs faster.")
    parser.add_argument("--rf007-rf008-session", type=Path, help="Armed external TCP MITM state file. Runs RF007/008 in the required UL7, DL7, UL8, DL8 order.")
    args = parser.parse_args()

    if args.all_threat_models:
        if args.scenario or args.rf007_rf008_session:
            parser.error("--all-threat-models cannot be combined with --scenario or --rf007-rf008-session")
        _run_all_threat_models(args)
        return

    threat_model = load_threat_model(args.threat_model, PROJECT_ROOT)
    if args.link not in threat_model.supported_links:
        parser.error(f"threat model {threat_model.id} does not support --link {args.link}")

    run_root = args.runs_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_rf_link_{threat_model.id}"
    if threat_model.id == "cryptographic-boundary":
        if args.rf007_rf008_session:
            _run_rf007_rf008_external_session(args=args, threat_model=threat_model, run_root=run_root)
            return
        _run_cryptographic_boundary(args=args, threat_model=threat_model, run_root=run_root)
        return

    environment = discover_link_environment(args.link, args.cosmos_container)
    _write_json(
        run_root / "threat_model.json",
        {
            "id": threat_model.id,
            "name": threat_model.name,
            "payload_format": threat_model.payload_format,
            "eavesdrop_success_if": threat_model.eavesdrop_success_if,
        },
    )
    directions = ("uplink", "downlink") if args.direction == "both" else (args.direction,)
    if args.capture_interface:
        environment = environment.__class__(**{**environment.__dict__, "bridge_interface": args.capture_interface})

    print(f"run: {run_root}")
    print(f"threat model: {threat_model.id}")
    print(f"link: {environment.link}")
    print(f"cosmos: {environment.cosmos_container} ({environment.cosmos_ip}, pid {environment.cosmos_pid})")
    print(f"target: {environment.target_name} {environment.target}")
    print(f"proxy host/listen: {environment.proxy_host}:{args.listen_port}")
    print(f"capture interface: {environment.bridge_interface}")
    if "downlink" in directions:
        print(
            f"{environment.link.upper()} downlink receiver: "
            f"{environment.cosmos_interface}:{environment.downlink_destination_port} "
            f"on {environment.downlink_destination_interface}"
        )
    scenarios = _select_scenarios(args.scenario, args.all)
    scores: list[LiveScore] = []
    if "uplink" in directions:
        owner = "suite" if args.all else "case"
        with _managed_uplink_interception_session(
            environment=environment,
            owner=owner,
            image=args.image,
            listen_port=args.listen_port,
            command_wait=args.command_wait,
            telemetry_timeout=args.telemetry_timeout,
            evidence_path=run_root / "uplink_interception_session.json",
            run_root=run_root,
        ) as uplink_session:
            scores.extend(
                _run_direction_cases(
                    direction="uplink",
                    scenarios=scenarios,
                    args=args,
                    environment=environment,
                    run_root=run_root,
                    uplink_session=uplink_session,
                )
            )
    if "downlink" in directions:
        owner = "suite" if args.all else "case"
        if environment.link == "radio":
            with _managed_radio_downlink_transport(
                environment=environment,
                owner=owner,
                ready_timeout=args.telemetry_timeout,
                evidence_path=run_root / "radio_downlink_session.json",
                image=args.image,
                listen_port=args.listen_port + 1,
                run_root=run_root,
            ) as radio_session:
                scores.extend(
                    _run_direction_cases(
                        direction="downlink",
                        scenarios=scenarios,
                        args=args,
                        environment=environment,
                        run_root=run_root,
                        radio_session=radio_session,
                    )
                )
        else:
            with _managed_debug_downlink_transport(
                environment=environment,
                owner=owner,
                ready_timeout=args.telemetry_timeout,
                evidence_path=run_root / "debug_downlink_session.json",
                image=args.image,
                listen_port=args.listen_port + 1,
                run_root=run_root,
            ) as debug_session:
                scores.extend(
                    _run_direction_cases(
                        direction="downlink",
                        scenarios=scenarios,
                        args=args,
                        environment=environment,
                        run_root=run_root,
                        debug_session=debug_session,
                    )
                )

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
    print(f"BATCH RESULT: {passed}/{len(scores)} direction cases passed")
    print(f"summary: {run_root / 'summary.md'}")


def _tcp_mitm_control(port: int, request: dict[str, object]) -> dict[str, object]:
    with socket.create_connection(("127.0.0.1", port), timeout=5.0) as connection:
        connection.sendall(json.dumps(request).encode("utf-8"))
        response = connection.recv(65535)
    result = json.loads(response.decode("utf-8"))
    if result.get("error"):
        raise RuntimeError(f"TCP MITM control error: {result['error']}")
    return result


def _run_rf007_rf008_external_session(*, args: argparse.Namespace, threat_model: ThreatModel, run_root: Path) -> None:
    """Execute one pre-armed, suite-owned external TCP MITM session.

    This is intentionally separate from legacy single-case runners: its sole
    supported order is RF007 uplink, RF007 downlink, RF008 uplink, RF008
    downlink, with no reconnection, service restart, or second launch between
    cases.
    """
    state_path = args.rf007_rf008_session
    if not state_path or not state_path.exists():
        raise SystemExit("--rf007-rf008-session must name the state file created by tcp_mitm_session prepare")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    try:
        environment = discover_link_environment("radio", args.cosmos_container)
        boundary = discover_cryptographic_boundary_environment_host_only(threat_model)
        initial = _tcp_mitm_control(int(state["control_port"]), {"action": "snapshot"})
    except Exception as error:
        raise SystemExit(f"external TCP MITM session is not ready: {error}") from error
    run_root.mkdir(parents=True, exist_ok=True)
    _write_json(run_root / "external_tcp_mitm_state.json", state)
    # Fixed order is part of the test invariant, independent of --direction.
    scenarios = [load_scenario(PROJECT_ROOT / "security_suites" / "rf_link" / "scenarios" / SCENARIO_FILES[identifier])
                 for identifier in ("RF-LINK-007", "RF-LINK-008")]
    order = [(scenarios[0], "uplink"), (scenarios[0], "downlink"), (scenarios[1], "uplink"), (scenarios[1], "downlink")]
    scores: list[LiveScore] = []
    print(f"run: {run_root}")
    print("external MITM session: ready; required order UL7 -> DL7 -> UL8 -> DL8")
    try:
        # The radio-sim -> CryptoLib stream is normally idle.  Enable its TO
        # output once for the entire suite and require a real RADIO packet
        # before considering either downlink attack executable.
        with _managed_radio_downlink_transport(
            environment=environment, owner="suite-owned-external-tcp-mitm",
            ready_timeout=max(args.telemetry_timeout, 20.0), evidence_path=run_root / "radio_downlink_session.json",
            image=args.image, listen_port=args.listen_port + 1, run_root=run_root, intercept_cosmos_downlink=False,
        ) as radio_session:
            for scenario, direction in order:
                commands = args.commands if args.commands is not None else (
                    DEFAULT_COMMANDS.get(scenario.id, 4) if direction == "uplink" else DEFAULT_DOWNLINK_STIMULI.get(scenario.id, 4)
                )
                if direction == "downlink" and not radio_session.ready:
                    scores.append(_cryptographic_boundary_not_ready_score(
                        scenario=scenario, direction=direction, threat_model=threat_model, radio_session=radio_session,
                    ))
                    continue
                scores.append(_run_external_tcp_mitm_case(
                    scenario=scenario, direction=direction, environment=environment, boundary_path=boundary.path_for(direction),
                    threat_model=threat_model, run_root=run_root, control_port=int(state["control_port"]), commands=commands,
                    command_wait=args.command_wait, telemetry_timeout=args.telemetry_timeout,
                ))
    finally:
        # Do not mask a case result if cleanup is imperfect.  The caller then
        # invokes tcp_mitm_session cleanup, which records a cleanup warning.
        try:
            final_snapshot = _tcp_mitm_control(int(state["control_port"]), {"action": "set", "mode": "observe", "direction": "uplink", "count": 0})
            _write_json(run_root / "external_tcp_mitm_final_snapshot.json", final_snapshot)
        except Exception as error:
            _append_json(run_root / "cleanup_warnings.jsonl", {"cleanup_warning": str(error)})
    _write_json(run_root / "summary.json", {"scores": [score.to_dict() for score in scores], "initial_session": initial})
    _write_batch_summary(run_root / "summary.md", scenarios, environment, scores)
    print(f"BATCH RESULT: {sum(score.passed for score in scores)}/{len(scores)} direction cases passed")
    print(f"summary: {run_root / 'summary.md'}")


def _run_all_threat_models(args: argparse.Namespace) -> None:
    """Run the user-facing whole RF benchmark without arming the RF007/008 MITM.

    RF007/RF008 deliberately remain outside this batch: their relay must be
    prepared before a dedicated NOS3 launch and would otherwise alter the
    protected RADIO path for unrelated cases.
    """
    batch_root = args.runs_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_rf_link_all_threat_models"
    common = [
        sys.executable,
        "-m",
        "benchmark_engine.rf_link.live_runner",
        "--direction",
        "both",
        "--image",
        args.image,
        "--listen-port",
        str(args.listen_port),
        "--command-wait",
        str(args.command_wait),
        "--telemetry-timeout",
        str(args.telemetry_timeout),
        "--duration",
        str(args.duration),
        "--cosmos-container",
        args.cosmos_container,
    ]
    if args.commands is not None:
        common.extend(["--commands", str(args.commands)])
    if args.capture_interface:
        common.extend(["--capture-interface", args.capture_interface])
    if args.health_each:
        common.append("--health-each")
    if args.skip_final_health:
        common.append("--skip-final-health")

    runs: list[tuple[str, list[str]]] = [
        (
            "trusted-domain DEBUG RF001-RF008",
            ["--all", "--link", "debug", "--threat-model", "trusted-domain"],
        ),
        (
            "trusted-domain RADIO RF001-RF008",
            ["--all", "--link", "radio", "--threat-model", "trusted-domain"],
        ),
    ]
    runs.extend(
        (
            f"cryptographic-boundary RADIO {scenario_id}",
            ["--scenario", scenario_id, "--link", "radio", "--threat-model", "cryptographic-boundary"],
        )
        for scenario_id in (
            "RF-LINK-001",
            "RF-LINK-002",
            "RF-LINK-003",
            "RF-LINK-004",
            "RF-LINK-005",
            "RF-LINK-006",
        )
    )

    print(f"whole RF benchmark: {batch_root}")
    print("plan: trusted-domain DEBUG/RADIO RF001-RF008, then cryptographic-boundary RADIO RF001-RF006")
    results: list[dict[str, object]] = []
    for ordinal, (label, tail) in enumerate(runs, start=1):
        child_root = batch_root / f"{ordinal:02d}_{label.lower().replace(' ', '_') }"
        command = [*common, *tail, "--runs-dir", str(child_root)]
        print()
        print(f"[{ordinal}/{len(runs)}] {label}")
        print("command: " + " ".join(command))
        result = subprocess.run(command, check=False)
        results.append({"label": label, "command": command, "returncode": result.returncode})
        print(f"[{ordinal}/{len(runs)}] {'OK' if result.returncode == 0 else f'EXIT {result.returncode}'}: {label}")

    _write_json(batch_root / "batch_commands.json", {"runs": results})
    failures = [item for item in results if int(item["returncode"]) != 0]
    print()
    print(f"WHOLE RF BATCH COMPLETE: {len(runs) - len(failures)}/{len(runs)} runner invocations exited successfully")
    print(f"batch commands: {batch_root / 'batch_commands.json'}")
    print()
    print("RF007/RF008 were intentionally not run. They require the dedicated external TCP MITM lifecycle:")
    print("  1. python3 -m benchmark_engine.rf_link.tcp_mitm_session prepare --state artifacts/rf007_rf008_mitm_state.json")
    print("  2. Restart or launch NOS3 once so the protected TCP connections enter the relay.")
    print("  3. python3 -m benchmark_engine.rf_link.live_runner --threat-model cryptographic-boundary --rf007-rf008-session artifacts/rf007_rf008_mitm_state.json")
    print("  4. python3 -m benchmark_engine.rf_link.tcp_mitm_session cleanup --state artifacts/rf007_rf008_mitm_state.json")


def _run_external_tcp_mitm_case(*, scenario: Scenario, direction: str, environment: LinkEnvironment,
                                boundary_path: CryptographicBoundaryPath, threat_model: ThreatModel, run_root: Path,
                                control_port: int, commands: int, command_wait: float, telemetry_timeout: float) -> LiveScore:
    scenario_dir = run_root / scenario.id / direction; scenario_dir.mkdir(parents=True, exist_ok=True)
    write_environment(scenario_dir / "environment.json", environment)
    _write_json(scenario_dir / "cryptographic_boundary_path.json", boundary_path.__dict__)
    mode = "fabricate" if scenario.id == "RF-LINK-007" else "reorder"
    count = max(1, int(scenario.attack.get("count", commands if mode == "reorder" else 1)))
    window = int(scenario.attack.get("window_size", 4))
    before = _tcp_mitm_control(control_port, {"action": "snapshot"})
    fsw = _resolve_container_name("nos-fsw"); since = time.time()
    error: str | None = None; stimuli: list[CosmosCommandResult] = []; recovery: list[CosmosCommandResult] = []
    try:
        armed = _tcp_mitm_control(control_port, {"action": "set", "mode": mode, "direction": direction,
                                                   "count": count, "window": window})
        if not bool(armed.get("frame_boundary_safe", {}).get(direction)):
            # The initial real frame is captured by the first normal stimulus;
            # attacks remain disabled until a later case only if it is unsafe.
            pass
        stimuli = (_send_cryptographic_boundary_uplink_stimuli(environment=environment, commands=commands, command_wait=command_wait, telemetry_timeout=telemetry_timeout)
                    if direction == "uplink" else _send_downlink_stimuli(environment=environment, commands=commands, command_wait=command_wait, telemetry_timeout=telemetry_timeout))
        _tcp_mitm_control(control_port, {"action": "set", "mode": "observe", "direction": direction, "count": 0})
        recovery = _wait_for_bridge_fault_recovery(direction=direction, environment=environment, command_wait=command_wait, telemetry_timeout=telemetry_timeout)
    except Exception as exc:
        error = str(exc)
    after = _tcp_mitm_control(control_port, {"action": "snapshot"})
    system = _read_system_response(fsw, since) if direction == "uplink" else {"executed_noop_count": 0, "error_event_count": 0}
    safe = bool(after.get("frame_boundary_safe", {}).get(direction)) and not after.get("frame_boundary_unsafe_reason", {}).get(direction)
    recovered = _successful_command_count(recovery)
    normal_success = _successful_command_count(stimuli)
    # A forged frame is unauthenticated.  The only acceptable cFS/COSMOS
    # outcome is attributable to the requested legitimate stimuli, never an
    # extra command or a trusted forged telemetry item.
    legitimate_budget = commands + len(recovery)
    no_unauthorized_effect = (
        int(system.get("executed_noop_count", 0)) <= legitimate_budget
        if direction == "uplink" else normal_success <= commands
    )
    recovery_confirmed = (
        bool(recovery) and all(item.ok for item in recovery)
        and int(after.get("recovered_frames", {}).get(direction, 0)) > int(before.get("recovered_frames", {}).get(direction, 0))
    )
    attacked = int(after.get("attack", {}).get("generation", 0)) > int(before.get("attack", {}).get("generation", 0))
    passed = error is None and safe and attacked and no_unauthorized_effect and recovery_confirmed
    effect = "blocked" if scenario.id == "RF-LINK-007" and passed else ("contained" if passed else "not_confirmed")
    evidence = {"threat_model": threat_model.id, "direction": direction, "path": boundary_path.__dict__,
                "attack_location": "external_active_mitm_between_cryptolib_and_radio_sim", "session_ownership": after.get("session_owner"),
                "endpoint_namespace_access": False, "service_restart": False, "session_before": before, "session_after": after,
                "stimulus_results": [item.raw for item in stimuli], "recovery_results": [item.raw for item in recovery],
                "receiver_behavior": system, "no_unauthorized_effect": no_unauthorized_effect,
                "legitimate_execution_budget": legitimate_budget, "recovery_confirmed": recovery_confirmed, "execution_error": error}
    score = LiveScore(scenario_id=scenario.id, direction=direction, passed=passed, threat_model=threat_model.id,
                      attack_effect=effect, evidence=evidence,
                      notes=[f"{mode}: complete-frame boundary safe={safe}; requested legitimate stimuli={commands}; recovery={recovered}/{len(recovery)}; external MITM only."] + ([f"execution error: {error}"] if error else []))
    _write_json(scenario_dir / "session_evidence_before.json", before); _write_json(scenario_dir / "session_evidence_after.json", after)
    _write_json(scenario_dir / "score.json", score.to_dict()); _write_cryptographic_boundary_summary(scenario_dir / "summary.md", score, boundary_path, {"source_payload_segments": 0, "destination_payload_segments": 0, "matching_payload_hashes": [], "complete_ccsds_segments": 0})
    print(f"{scenario.id} [{direction}]: {'PASS' if passed else 'FAIL'}")
    return score


def _run_cryptographic_boundary(*, args: argparse.Namespace, threat_model: ThreatModel, run_root: Path) -> None:
    """Run cases from the CryptoLib-radio-sim side of the security boundary.

    RF001 is intentionally passive. Active cases operate only on a host-veth
    representing the external transport medium; they never replace or reset
    an established CryptoLib/radio-sim TCP connection.
    """
    scenarios = _select_scenarios(args.scenario, args.all)
    directions = ("uplink", "downlink") if args.direction == "both" else (args.direction,)
    try:
        environment = discover_link_environment("radio", args.cosmos_container)
        boundary = discover_cryptographic_boundary_environment(threat_model)
    except (RuntimeError, subprocess.CalledProcessError, IndexError) as error:
        _write_cryptographic_boundary_unavailable(
            run_root=run_root,
            scenario=scenarios[0],
            directions=directions,
            threat_model=threat_model,
            error=error,
        )
        return
    _write_json(
        run_root / "threat_model.json",
        {
            "id": threat_model.id,
            "name": threat_model.name,
            "payload_format": threat_model.payload_format,
            "eavesdrop_success_if": threat_model.eavesdrop_success_if,
        },
    )

    print(f"run: {run_root}")
    print(f"threat model: {threat_model.id}")
    print("payload format: protected_frame (TCP; no CCSDS metadata is assumed authoritative)")
    for direction in directions:
        path = boundary.path_for(direction)
        print(
            f"{direction} protected path: {path.source_container}:{path.source_interface} "
            f"-> {path.destination_container}:{path.destination_interface}:{path.destination_port} ({path.transport})"
        )

    scores: list[LiveScore] = []
    with _managed_radio_downlink_transport(
        environment=environment,
        owner="suite" if args.all else "case",
        # CryptoLib/radio-sim needs longer than the generic command polling
        # timeout after a NOS3 launch.  Do not start a boundary case before a
        # real CFS_RADIO housekeeping packet has arrived.
        ready_timeout=max(args.telemetry_timeout, 20.0),
        evidence_path=run_root / "radio_downlink_session.json",
        image=args.image,
        listen_port=args.listen_port + 1,
        run_root=run_root,
        intercept_cosmos_downlink=False,
    ) as radio_session:
        for scenario in scenarios:
            for direction in directions:
                commands = args.commands if args.commands is not None else (
                    DEFAULT_COMMANDS.get(scenario.id, 1) if direction == "uplink" else DEFAULT_DOWNLINK_STIMULI.get(scenario.id, 1)
                )
                if not radio_session.ready:
                    scores.append(
                        _cryptographic_boundary_not_ready_score(
                            scenario=scenario,
                            direction=direction,
                            threat_model=threat_model,
                            radio_session=radio_session,
                        )
                    )
                    continue
                if scenario.id == "RF-LINK-001":
                    scores.append(
                        _run_cryptographic_boundary_rf001(
                            scenario=scenario, direction=direction, environment=environment,
                            boundary_path=boundary.path_for(direction), threat_model=threat_model,
                            run_root=run_root, image=args.image, commands=commands,
                            command_wait=args.command_wait, telemetry_timeout=args.telemetry_timeout,
                            duration=args.duration, radio_session=radio_session,
                        )
                    )
                elif scenario.id == "RF-LINK-002":
                    scores.append(
                        _run_cryptographic_boundary_bridge_drop(
                            scenario=scenario, direction=direction, environment=environment,
                            boundary_path=boundary.path_for(direction), threat_model=threat_model,
                            run_root=run_root, image=args.image, commands=commands,
                            command_wait=args.command_wait, telemetry_timeout=args.telemetry_timeout,
                            duration=args.duration,
                        )
                    )
                elif scenario.id == "RF-LINK-003":
                    scores.append(
                        _run_cryptographic_boundary_bridge_delay(
                            scenario=scenario, direction=direction, environment=environment,
                            boundary_path=boundary.path_for(direction), threat_model=threat_model,
                            run_root=run_root, image=args.image, commands=commands,
                            command_wait=args.command_wait, telemetry_timeout=args.telemetry_timeout,
                            duration=args.duration,
                        )
                    )
                elif scenario.id == "RF-LINK-005":
                    scores.append(
                        _run_cryptographic_boundary_bridge_mutation(
                            scenario=scenario, direction=direction, environment=environment,
                            boundary_path=boundary.path_for(direction), threat_model=threat_model,
                            run_root=run_root, image=args.image, commands=commands,
                            command_wait=args.command_wait, telemetry_timeout=args.telemetry_timeout,
                            duration=args.duration,
                        )
                    )
                elif scenario.id == "RF-LINK-006":
                    scores.append(
                        _run_cryptographic_boundary_flood_smoke(
                            scenario=scenario, direction=direction, environment=environment,
                            boundary_path=boundary.path_for(direction), threat_model=threat_model,
                            run_root=run_root, image=args.image, command_wait=args.command_wait,
                            telemetry_timeout=args.telemetry_timeout,
                        )
                    )
                else:
                    scores.append(
                        _cryptographic_boundary_not_implemented_score(
                            scenario=scenario,
                            direction=direction,
                            boundary_path=boundary.path_for(direction),
                            threat_model=threat_model,
                            run_root=run_root,
                        )
                    )
        if args.skip_final_health:
            _append_json(run_root / "health_checks.jsonl", {"skipped": True, "reason": "skip-final-health"})
        else:
            health = _run_health_check(environment, args.command_wait, args.telemetry_timeout)
            _append_json(run_root / "health_checks.jsonl", health.raw)
            print(f"final health: {'OK' if health.ok and (health.counter_delta or 0) > 0 else 'NOT CONFIRMED'}")

    _write_batch_summary(run_root / "summary.md", scenarios, environment, scores)
    _write_json(run_root / "summary.json", {"scores": [score.to_dict() for score in scores]})
    passed = sum(1 for score in scores if score.passed)
    print()
    print(f"BATCH RESULT: {passed}/{len(scores)} direction cases passed")
    print(f"summary: {run_root / 'summary.md'}")


def _cryptographic_boundary_not_ready_score(
    *,
    scenario: Scenario,
    direction: str,
    threat_model: ThreatModel,
    radio_session: RadioDownlinkSession,
) -> LiveScore:
    return LiveScore(
        scenario_id=scenario.id,
        direction=direction,
        passed=False,
        threat_model=threat_model.id,
        attack_effect="unavailable",
        evidence={
            "threat_model": threat_model.id,
            "direction": direction,
            "radio_downlink_session": radio_session.snapshot(),
            "preflight_error": "RADIO CFS_RADIO SC_HKTLM was not observed; TCP attack relay was not started.",
        },
        notes=[
            "RADIO health precondition failed, so no TCP attack or connection reset was attempted.",
            "This is an execution-precondition FAIL, not an attack-blocked conclusion.",
        ],
    )


def _cryptographic_boundary_not_implemented_score(
    *,
    scenario: Scenario,
    direction: str,
    boundary_path: CryptographicBoundaryPath,
    threat_model: ThreatModel,
    run_root: Path,
) -> LiveScore:
    requires_frame_injection = scenario.id in {"RF-LINK-004", "RF-LINK-007", "RF-LINK-008"}
    limitation = (
        "The NOS3 protected path is an established TCP byte stream with no protected-frame length boundary. "
        "Replaying, fabricating, or reordering a captured TCP segment is handled by TCP before CryptoLib and is not an anti-replay/authentication test. "
        "Its receiver accepts one startup connection only, so a second attacker connection cannot deliver an independent protected frame."
        if requires_frame_injection
        else
        "The NOS3 virtual TCP path has no RF-medium capacity or scheduler model. A connection-attempt or arbitrary Ethernet flood would not exercise CryptoLib's protected-frame receive path and would not establish a service-DoS conclusion."
    )
    score = LiveScore(
        scenario_id=scenario.id,
        direction=direction,
        passed=False,
        threat_model=threat_model.id,
        attack_effect="unsupported_by_transport_model",
        evidence={
            "threat_model": threat_model.id,
            "direction": direction,
            "path": boundary_path.__dict__,
            "transport_model": {
                "transport": "tcp",
                "protected_frame_boundary": "not_exposed",
                "independent_attacker_connection": "not_delivered_to_active_receiver",
            },
            "preflight_error": limitation,
        },
        notes=[
            "No attack ran. The obsolete reconnect-proxy implementation remains removed.",
            limitation,
        ],
    )
    scenario_dir = run_root / scenario.id / direction
    scenario_dir.mkdir(parents=True, exist_ok=True)
    _write_json(scenario_dir / "cryptographic_boundary_path.json", boundary_path.__dict__)
    _write_json(scenario_dir / "score.json", score.to_dict())
    _write_cryptographic_boundary_summary(scenario_dir / "summary.md", score, boundary_path, {
        "source_payload_segments": 0,
        "destination_payload_segments": 0,
        "matching_payload_hashes": [],
        "complete_ccsds_segments": 0,
    })
    return score


def _write_cryptographic_boundary_unavailable(
    *,
    run_root: Path,
    scenario: Scenario,
    directions: tuple[str, ...],
    threat_model: ThreatModel,
    error: Exception,
) -> None:
    """Record topology unavailability as a failed test, not a security verdict."""
    reason = f"cryptographic-boundary topology unavailable: {error}"
    scores: list[LiveScore] = []
    for direction in directions:
        scenario_dir = run_root / scenario.id / direction
        scenario_dir.mkdir(parents=True, exist_ok=True)
        score = LiveScore(
            scenario_id=scenario.id,
            direction=direction,
            passed=False,
            threat_model=threat_model.id,
            attack_effect="unavailable",
            evidence={
                "threat_model": threat_model.id,
                "payload_format": threat_model.payload_format,
                "preflight_error": reason,
            },
            notes=[
                "This is an execution-precondition failure, not evidence that cryptographic protection blocked an attack.",
                reason,
            ],
        )
        scores.append(score)
        _write_json(scenario_dir / "score.json", score.to_dict())
    _write_json(run_root / "summary.json", {"scores": [score.to_dict() for score in scores]})
    summary = "\n".join(
        [
            "# Cryptographic-Boundary RF-Link Summary",
            "",
            f"- Threat model: `{threat_model.id}`",
            "- Result: `FAIL` (topology unavailable)",
            f"- Preflight error: `{reason}`",
            "",
            "No security conclusion was produced because the CryptoLib-radio-sim protected path was not live.",
            "",
        ]
    )
    (run_root / "summary.md").write_text(summary, encoding="utf-8")
    print(f"cryptographic-boundary preflight: FAIL ({reason})")
    print(f"summary: {run_root / 'summary.md'}")


def _run_cryptographic_boundary_rf001(
    *,
    scenario: Scenario,
    direction: str,
    environment: LinkEnvironment,
    boundary_path: CryptographicBoundaryPath,
    threat_model: ThreatModel,
    run_root: Path,
    image: str,
    commands: int,
    command_wait: float,
    telemetry_timeout: float,
    duration: float,
    radio_session: RadioDownlinkSession | None = None,
) -> LiveScore:
    scenario_dir = run_root / scenario.id / direction
    scenario_dir.mkdir(parents=True, exist_ok=True)
    write_environment(scenario_dir / "environment.json", environment)
    _write_json(scenario_dir / "cryptographic_boundary_path.json", boundary_path.__dict__)

    source_observation = scenario_dir / "source_packet_observations.jsonl"
    destination_observation = scenario_dir / "destination_packet_observations.jsonl"
    source_capture = TcpdumpCapture(
        interface=boundary_path.source_interface,
        pcap_path=scenario_dir / "source_packets.pcap",
        observation_path=source_observation,
        ports=[boundary_path.destination_port],
        image=image,
        mount_root=PROJECT_ROOT,
        duration=max(duration, commands * max(command_wait, 0.25) + telemetry_timeout + 4.0),
        network_container=boundary_path.source_container,
        transport=boundary_path.transport,
    )
    destination_capture = TcpdumpCapture(
        interface=boundary_path.destination_interface,
        pcap_path=scenario_dir / "destination_packets.pcap",
        observation_path=destination_observation,
        ports=[boundary_path.destination_port],
        image=image,
        mount_root=PROJECT_ROOT,
        duration=max(duration, commands * max(command_wait, 0.25) + telemetry_timeout + 4.0),
        network_container=boundary_path.destination_container,
        transport=boundary_path.transport,
    )

    print()
    print(f"scenario: {scenario.id} {scenario.name} [{direction}; {threat_model.id}]")
    print(
        f"observer: {boundary_path.source_container}:{boundary_path.source_interface} -> "
        f"{boundary_path.destination_container}:{boundary_path.destination_interface}:{boundary_path.destination_port}"
    )
    with _capture_contexts([source_capture, destination_capture]):
        if direction == "uplink":
            stimuli = _send_cryptographic_boundary_uplink_stimuli(
                environment=environment,
                commands=commands,
                command_wait=command_wait,
                telemetry_timeout=telemetry_timeout,
            )
        else:
            if radio_session is None or not radio_session.ready:
                stimuli = []
            else:
                stimuli = _send_downlink_stimuli(
                    environment=environment,
                    commands=commands,
                    command_wait=command_wait,
                    telemetry_timeout=telemetry_timeout,
                )
        time.sleep(0.75)

    source_packets = _read_transport_observations(source_observation, boundary_path.transport)
    destination_packets = _read_transport_observations(destination_observation, boundary_path.transport)
    packet_summary = _summarize_cryptographic_boundary_packets(source_packets, destination_packets)
    successful_stimuli = _successful_command_count(stimuli)
    plaintext_visible = bool(packet_summary["complete_ccsds_segments"])
    captured = int(packet_summary["source_payload_segments"]) > 0 and int(packet_summary["destination_payload_segments"]) > 0
    delivered = bool(packet_summary["matching_payload_hashes"])
    attack_succeeded = captured and delivered and plaintext_visible and successful_stimuli > 0
    attack_effect = "observed" if attack_succeeded else "blocked"
    notes = [
        "PASS means the external eavesdropping attack exposed a complete plaintext CCSDS segment on the CryptoLib-radio-sim protected TCP path.",
    ]
    if attack_succeeded:
        notes.append("Complete plaintext CCSDS data was visible at the cryptographic boundary.")
    elif captured and delivered and successful_stimuli > 0:
        notes.append("Protected TCP traffic was observed and delivered, but no complete plaintext CCSDS segment was visible; the eavesdropping attack did not succeed.")
    else:
        notes.append("The protected-path observation or the normal traffic stimulus was not confirmed; inspect capture diagnostics before drawing a cryptographic conclusion.")

    _write_json(scenario_dir / "packet_summary.json", packet_summary)
    _write_json(scenario_dir / "telemetry_stimulus.json", [result.raw for result in stimuli])
    score = LiveScore(
        scenario_id=scenario.id,
        direction=direction,
        passed=attack_succeeded,
        threat_model=threat_model.id,
        attack_effect=attack_effect,
        evidence={
            "threat_model": threat_model.id,
            "payload_format": threat_model.payload_format,
            "path": boundary_path.__dict__,
            "packet_summary": packet_summary,
            "successful_stimuli": successful_stimuli,
            "requested_stimuli": len(stimuli),
            "attack_success_if": threat_model.eavesdrop_success_if,
        },
        notes=notes,
    )
    _write_json(scenario_dir / "score.json", score.to_dict())
    _write_cryptographic_boundary_summary(scenario_dir / "summary.md", score, boundary_path, packet_summary)
    return score


def _run_cryptographic_boundary_bridge_drop(
    *,
    scenario: Scenario,
    direction: str,
    environment: LinkEnvironment,
    boundary_path: CryptographicBoundaryPath,
    threat_model: ThreatModel,
    run_root: Path,
    image: str,
    commands: int,
    command_wait: float,
    telemetry_timeout: float,
    duration: float,
) -> LiveScore:
    """RF002 fault injection on the shared RF/transport medium, not endpoints."""
    scenario_dir = run_root / scenario.id / direction
    scenario_dir.mkdir(parents=True, exist_ok=True)
    write_environment(scenario_dir / "environment.json", environment)
    _write_json(scenario_dir / "cryptographic_boundary_path.json", boundary_path.__dict__)
    source_observation = scenario_dir / "source_packet_observations.jsonl"
    destination_observation = scenario_dir / "destination_packet_observations.jsonl"
    captures = [
        TcpdumpCapture(interface=boundary_path.source_interface, pcap_path=scenario_dir / "source_packets.pcap", observation_path=source_observation, ports=[boundary_path.destination_port], image=image, mount_root=PROJECT_ROOT, duration=max(duration + 20, 35), network_container=boundary_path.source_container, transport="tcp"),
        TcpdumpCapture(interface=boundary_path.destination_interface, pcap_path=scenario_dir / "destination_packets.pcap", observation_path=destination_observation, ports=[boundary_path.destination_port], image=image, mount_root=PROJECT_ROOT, duration=max(duration + 20, 35), network_container=boundary_path.destination_container, transport="tcp"),
    ]
    fault = ProtectedBridgeDrop(path=boundary_path, preference=49000 + int(scenario.id.rsplit("-", 1)[-1]) * 2 + (0 if direction == "uplink" else 1), image=image)
    stimuli: list[CosmosCommandResult] = []
    recovery: list[CosmosCommandResult] = []
    fault_evidence: dict[str, object] = {}
    error: str | None = None
    print()
    print(f"scenario: {scenario.id} {scenario.name} [{direction}; {threat_model.id}; shared bridge drop]")
    try:
        with _capture_contexts(captures):
            fault.start()
            try:
                if direction == "uplink":
                    stimuli = _send_cryptographic_boundary_uplink_stimuli(environment=environment, commands=commands, command_wait=command_wait, telemetry_timeout=telemetry_timeout)
                else:
                    stimuli = _send_downlink_stimuli(environment=environment, commands=commands, command_wait=command_wait, telemetry_timeout=telemetry_timeout)
            finally:
                fault_evidence = fault.stop()
            recovery = _wait_for_bridge_fault_recovery(direction=direction, environment=environment, command_wait=command_wait, telemetry_timeout=telemetry_timeout)
    except Exception as exc:
        error = str(exc)
        if fault.installed:
            try:
                fault_evidence = fault.stop()
            except Exception as cleanup_error:
                fault_evidence["cleanup_warning"] = str(cleanup_error)
    source_packets = _read_transport_observations(source_observation, "tcp")
    destination_packets = _read_transport_observations(destination_observation, "tcp")
    packet_summary = _summarize_cryptographic_boundary_packets(source_packets, destination_packets)
    requested = _sent_command_count(stimuli)
    successful = _successful_command_count(stimuli)
    recovered = _successful_command_count(recovery)
    dropped = int(fault_evidence.get("packets", 0))
    source_payloads = int(packet_summary.get("source_payload_segments", 0))
    destination_payloads = int(packet_summary.get("destination_payload_segments", 0))
    observed_drop = dropped > 0 or source_payloads > destination_payloads
    cleaned = bool(fault_evidence.get("filter_removed"))
    passed = error is None and bool(fault_evidence.get("found")) and observed_drop and successful < requested and recovered > 0 and cleaned
    score = LiveScore(
        scenario_id=scenario.id, direction=direction, passed=passed, threat_model=threat_model.id,
        attack_effect="observed" if passed else "not_confirmed",
        evidence={"threat_model": threat_model.id, "direction": direction, "path": boundary_path.__dict__, "packet_summary": packet_summary, "bridge_fault": fault_evidence, "stimulus_results": [result.raw for result in stimuli], "recovery_results": [result.raw for result in recovery], "cleanup": {"filter_removed": cleaned, "endpoint_namespace_access": False, "no_process_restart": True}, "execution_error": error},
        notes=[f"shared-medium tc packets={dropped}; source/destination payload={source_payloads}/{destination_payloads}; impaired stimuli={successful}/{requested}; recovery={recovered}/{len(recovery)}; filter_removed={cleaned}."] + ([f"execution error: {error}"] if error else []),
    )
    _write_json(scenario_dir / "packet_summary.json", packet_summary)
    _write_json(scenario_dir / "bridge_fault_evidence.json", fault_evidence)
    _write_json(scenario_dir / "stimulus_results.json", [result.raw for result in stimuli])
    _write_json(scenario_dir / "recovery_health.json", [result.raw for result in recovery])
    _write_json(scenario_dir / "score.json", score.to_dict())
    _write_cryptographic_boundary_summary(scenario_dir / "summary.md", score, boundary_path, packet_summary)
    return score


def _wait_for_bridge_fault_recovery(*, direction: str, environment: LinkEnvironment, command_wait: float, telemetry_timeout: float) -> list[CosmosCommandResult]:
    attempts: list[CosmosCommandResult] = []
    for attempt in range(4):
        result = (
            _send_cryptographic_boundary_uplink_stimuli(environment=environment, commands=1, command_wait=command_wait, telemetry_timeout=max(telemetry_timeout, 10.0))
            if direction == "uplink"
            else _send_downlink_stimuli(environment=environment, commands=1, command_wait=command_wait, telemetry_timeout=max(telemetry_timeout, 10.0))
        )
        attempts.extend(result)
        if _successful_command_count(result) > 0:
            break
        if attempt < 3:
            time.sleep(2.0)
    return attempts


def _run_cryptographic_boundary_bridge_delay(
    *,
    scenario: Scenario,
    direction: str,
    environment: LinkEnvironment,
    boundary_path: CryptographicBoundaryPath,
    threat_model: ThreatModel,
    run_root: Path,
    image: str,
    commands: int,
    command_wait: float,
    telemetry_timeout: float,
    duration: float,
) -> LiveScore:
    scenario_dir = run_root / scenario.id / direction
    scenario_dir.mkdir(parents=True, exist_ok=True)
    write_environment(scenario_dir / "environment.json", environment)
    _write_json(scenario_dir / "cryptographic_boundary_path.json", boundary_path.__dict__)
    source_observation = scenario_dir / "source_packet_observations.jsonl"
    destination_observation = scenario_dir / "destination_packet_observations.jsonl"
    delay_ms = int(scenario.attack.get("delay_ms", 1000))
    captures = [
        TcpdumpCapture(interface=boundary_path.source_interface, pcap_path=scenario_dir / "source_packets.pcap", observation_path=source_observation, ports=[boundary_path.destination_port], image=image, mount_root=PROJECT_ROOT, duration=max(duration + commands * (telemetry_timeout + 2) + 15, 40), network_container=boundary_path.source_container, transport="tcp"),
        TcpdumpCapture(interface=boundary_path.destination_interface, pcap_path=scenario_dir / "destination_packets.pcap", observation_path=destination_observation, ports=[boundary_path.destination_port], image=image, mount_root=PROJECT_ROOT, duration=max(duration + commands * (telemetry_timeout + 2) + 15, 40), network_container=boundary_path.destination_container, transport="tcp"),
    ]
    fault = ProtectedMediumDelay(path=boundary_path, preference=49100 + int(scenario.id.rsplit("-", 1)[-1]) * 2 + (0 if direction == "uplink" else 1), delay_ms=delay_ms, image=image)
    stimuli: list[CosmosCommandResult] = []
    evidence: dict[str, object] = {}
    error: str | None = None
    try:
        with _capture_contexts(captures):
            fault.start()
            try:
                stimuli = (
                    _send_cryptographic_boundary_uplink_stimuli(environment=environment, commands=commands, command_wait=command_wait, telemetry_timeout=telemetry_timeout)
                    if direction == "uplink"
                    else _send_downlink_stimuli(environment=environment, commands=commands, command_wait=command_wait, telemetry_timeout=telemetry_timeout)
                )
            finally:
                evidence = fault.stop()
    except Exception as exc:
        error = str(exc)
        if fault.installed:
            try:
                evidence = fault.stop()
            except Exception as cleanup_error:
                evidence["cleanup_warning"] = str(cleanup_error)
    source_packets = _read_transport_observations(source_observation, "tcp")
    destination_packets = _read_transport_observations(destination_observation, "tcp")
    packet_summary = _summarize_cryptographic_boundary_packets(source_packets, destination_packets)
    max_delay = _max_transport_delay(source_packets, destination_packets)
    expected = delay_ms / 1000.0
    passed = error is None and bool(evidence.get("filter")) and max_delay is not None and max_delay >= expected * 0.8 and bool(evidence.get("qdisc_removed"))
    score = LiveScore(
        scenario_id=scenario.id, direction=direction, passed=passed, threat_model=threat_model.id,
        attack_effect="observed" if passed else "not_confirmed",
        evidence={"threat_model": threat_model.id, "direction": direction, "path": boundary_path.__dict__, "packet_summary": packet_summary, "delay_fault": evidence, "max_observed_delay_seconds": max_delay, "stimulus_results": [result.raw for result in stimuli], "cleanup": {"qdisc_removed": bool(evidence.get("qdisc_removed")), "endpoint_namespace_access": False, "no_process_restart": True}, "execution_error": error},
        notes=[f"configured delay={expected}s; max observed source-to-destination delay={max_delay}s."] + ([f"execution error: {error}"] if error else []),
    )
    _write_json(scenario_dir / "packet_summary.json", packet_summary)
    _write_json(scenario_dir / "delay_fault_evidence.json", evidence)
    _write_json(scenario_dir / "stimulus_results.json", [result.raw for result in stimuli])
    _write_json(scenario_dir / "score.json", score.to_dict())
    _write_cryptographic_boundary_summary(scenario_dir / "summary.md", score, boundary_path, packet_summary)
    return score


def _run_cryptographic_boundary_bridge_mutation(
    *,
    scenario: Scenario,
    direction: str,
    environment: LinkEnvironment,
    boundary_path: CryptographicBoundaryPath,
    threat_model: ThreatModel,
    run_root: Path,
    image: str,
    commands: int,
    command_wait: float,
    telemetry_timeout: float,
    duration: float,
) -> LiveScore:
    """RF005: deliver an altered protected payload with a valid TCP checksum."""
    scenario_dir = run_root / scenario.id / direction
    scenario_dir.mkdir(parents=True, exist_ok=True)
    write_environment(scenario_dir / "environment.json", environment)
    _write_json(scenario_dir / "cryptographic_boundary_path.json", boundary_path.__dict__)
    source_observation = scenario_dir / "source_packet_observations.jsonl"
    destination_observation = scenario_dir / "destination_packet_observations.jsonl"
    captures = [
        TcpdumpCapture(interface=boundary_path.source_interface, pcap_path=scenario_dir / "source_packets.pcap", observation_path=source_observation, ports=[boundary_path.destination_port], image=image, mount_root=PROJECT_ROOT, duration=max(duration + commands * (telemetry_timeout + 2) + 15, 40), network_container=boundary_path.source_container, transport="tcp"),
        TcpdumpCapture(interface=boundary_path.destination_interface, pcap_path=scenario_dir / "destination_packets.pcap", observation_path=destination_observation, ports=[boundary_path.destination_port], image=image, mount_root=PROJECT_ROOT, duration=max(duration + commands * (telemetry_timeout + 2) + 15, 40), network_container=boundary_path.destination_container, transport="tcp"),
    ]
    mutation = ProtectedBridgeCiphertextMutation(
        path=boundary_path,
        preference=49200 + (0 if direction == "uplink" else 1),
        payload_offset_from_ip=int(scenario.attack.get("protected_payload_offset_from_ip", 76)),
        image=image,
    )
    stimuli: list[CosmosCommandResult] = []
    recovery: list[CosmosCommandResult] = []
    evidence: dict[str, object] = {}
    error: str | None = None
    print()
    print(f"scenario: {scenario.id} {scenario.name} [{direction}; {threat_model.id}; protected payload mutation]")
    try:
        with _capture_contexts(captures):
            mutation.start()
            try:
                stimuli = (
                    _send_cryptographic_boundary_uplink_stimuli(environment=environment, commands=commands, command_wait=command_wait, telemetry_timeout=telemetry_timeout)
                    if direction == "uplink"
                    else _send_downlink_stimuli(environment=environment, commands=commands, command_wait=command_wait, telemetry_timeout=telemetry_timeout)
                )
            finally:
                evidence = mutation.stop()
            recovery = _wait_for_bridge_fault_recovery(direction=direction, environment=environment, command_wait=command_wait, telemetry_timeout=telemetry_timeout)
    except Exception as exc:
        error = str(exc)
        if mutation.installed:
            try:
                evidence = mutation.stop()
            except Exception as cleanup_error:
                evidence["cleanup_warning"] = str(cleanup_error)
    source_packets = _read_transport_observations(source_observation, "tcp")
    destination_packets = _read_transport_observations(destination_observation, "tcp")
    packet_summary = _summarize_cryptographic_boundary_packets(source_packets, destination_packets)
    source_hashes = set(packet_summary["source_payload_hashes"])
    destination_hashes = set(packet_summary["destination_payload_hashes"])
    mutated_on_wire = bool(source_hashes - destination_hashes) and bool(destination_hashes - source_hashes)
    requested = _sent_command_count(stimuli)
    successful = _successful_command_count(stimuli)
    recovered = _successful_command_count(recovery)
    cleaned = bool(evidence.get("filter_removed"))
    passed = error is None and bool(evidence.get("found")) and mutated_on_wire and successful < requested and recovered > 0 and cleaned
    score = LiveScore(
        scenario_id=scenario.id, direction=direction, passed=passed, threat_model=threat_model.id,
        attack_effect="blocked" if passed else "not_confirmed",
        evidence={"threat_model": threat_model.id, "direction": direction, "path": boundary_path.__dict__, "packet_summary": packet_summary, "ciphertext_mutation": evidence, "mutated_on_wire": mutated_on_wire, "stimulus_results": [result.raw for result in stimuli], "recovery_results": [result.raw for result in recovery], "cleanup": {"filter_removed": cleaned, "endpoint_namespace_access": False, "no_process_restart": True}, "execution_error": error},
        notes=[f"pedit changed protected TCP payload bytes with TCP checksum recomputation; wire mutation={mutated_on_wire}; impaired stimuli={successful}/{requested}; recovery={recovered}/{len(recovery)}; filter_removed={cleaned}."] + ([f"execution error: {error}"] if error else []),
    )
    _write_json(scenario_dir / "packet_summary.json", packet_summary)
    _write_json(scenario_dir / "ciphertext_mutation_evidence.json", evidence)
    _write_json(scenario_dir / "stimulus_results.json", [result.raw for result in stimuli])
    _write_json(scenario_dir / "recovery_health.json", [result.raw for result in recovery])
    _write_json(scenario_dir / "score.json", score.to_dict())
    _write_cryptographic_boundary_summary(scenario_dir / "summary.md", score, boundary_path, packet_summary)
    return score


def _run_cryptographic_boundary_flood_smoke(
    *,
    scenario: Scenario,
    direction: str,
    environment: LinkEnvironment,
    boundary_path: CryptographicBoundaryPath,
    threat_model: ThreatModel,
    run_root: Path,
    image: str,
    command_wait: float,
    telemetry_timeout: float,
) -> LiveScore:
    """RF006: bounded external-medium injection, not a CryptoLib DoS claim."""
    scenario_dir = run_root / scenario.id / direction
    scenario_dir.mkdir(parents=True, exist_ok=True)
    write_environment(scenario_dir / "environment.json", environment)
    _write_json(scenario_dir / "cryptographic_boundary_path.json", boundary_path.__dict__)
    observation_path = scenario_dir / "destination_packet_observations.jsonl"
    rate = float(scenario.attack.get("rate_per_second", 20))
    payload_size = int(scenario.attack.get("payload_size", 64))
    flood_duration = float(scenario.attack.get("flood_duration_seconds", 10))
    capture = TcpdumpCapture(
        interface=boundary_path.destination_interface,
        pcap_path=scenario_dir / "destination_packets.pcap",
        observation_path=observation_path,
        ports=[boundary_path.destination_port],
        image=image,
        mount_root=PROJECT_ROOT,
        duration=max(flood_duration + 8, 20),
        network_container=boundary_path.destination_container,
        transport="tcp",
    )
    flood = ProtectedMediumFlood(
        path=boundary_path,
        project_root=PROJECT_ROOT,
        rate_per_second=rate,
        payload_size=payload_size,
        duration_seconds=flood_duration,
        image=image,
    )
    evidence: dict[str, object] = {}
    recovery: list[CosmosCommandResult] = []
    error: str | None = None
    print()
    print(f"scenario: {scenario.id} {scenario.name} [{direction}; {threat_model.id}; bounded transport flood smoke]")
    try:
        with _capture_contexts([capture]):
            evidence = flood.run()
        recovery = _wait_for_bridge_fault_recovery(direction=direction, environment=environment, command_wait=command_wait, telemetry_timeout=telemetry_timeout)
    except Exception as exc:
        error = str(exc)
    observations = _read_transport_observations(observation_path, "tcp")
    attacker_ip = str(evidence.get("attacker_ip", "198.18.0.1"))
    observed_frames = sum(1 for item in observations if item.get("source") == attacker_ip and int(item.get("length", 0) or 0) == payload_size)
    sent_frames = int(evidence.get("sent_frames", 0))
    recovered = _successful_command_count(recovery)
    passed = error is None and sent_frames > 0 and observed_frames >= max(1, int(sent_frames * 0.8)) and recovered > 0
    score = LiveScore(
        scenario_id=scenario.id, direction=direction, passed=passed, threat_model=threat_model.id,
        attack_effect="transport_injection_observed" if passed else "not_confirmed",
        evidence={"threat_model": threat_model.id, "direction": direction, "path": boundary_path.__dict__, "flood": evidence, "destination_observed_frames": observed_frames, "recovery_results": [result.raw for result in recovery], "execution_error": error},
        notes=[f"Bounded invalid TCP payload injection: sent={sent_frames}, destination-observed={observed_frames}, recovery={recovered}/{len(recovery)}. This is a transport-pressure smoke test, not evidence that CryptoLib or the mission service was DoS'd."] + ([f"execution error: {error}"] if error else []),
    )
    _write_json(scenario_dir / "flood_evidence.json", evidence)
    _write_json(scenario_dir / "destination_packet_observations.json", observations)
    _write_json(scenario_dir / "recovery_health.json", [result.raw for result in recovery])
    _write_json(scenario_dir / "score.json", score.to_dict())
    _write_cryptographic_boundary_summary(scenario_dir / "summary.md", score, boundary_path, {
        "source_payload_segments": 0,
        "destination_payload_segments": observed_frames,
        "matching_payload_hashes": [],
        "complete_ccsds_segments": 0,
    })
    return score


def _max_transport_delay(source_packets: list[dict[str, object]], destination_packets: list[dict[str, object]]) -> float | None:
    source_times: dict[str, deque[float]] = defaultdict(deque)
    for packet in source_packets:
        payload_hash = packet.get("payload_sha256")
        if payload_hash and int(packet.get("length", 0) or 0) > 0:
            source_times[str(payload_hash)].append(float(packet.get("timestamp", 0.0)))
    delays: list[float] = []
    for packet in destination_packets:
        payload_hash = packet.get("payload_sha256")
        if not payload_hash or int(packet.get("length", 0) or 0) <= 0:
            continue
        queue = source_times.get(str(payload_hash))
        if queue:
            delays.append(max(0.0, float(packet.get("timestamp", 0.0)) - queue.popleft()))
    return max(delays) if delays else None


def _send_cryptographic_boundary_uplink_stimuli(
    *,
    environment: LinkEnvironment,
    commands: int,
    command_wait: float,
    telemetry_timeout: float,
) -> list[CosmosCommandResult]:
    return [
        send_noop_and_read_counter(
            container=environment.cosmos_container,
            target=environment.cosmos_target,
            command=environment.noop_command,
            housekeeping_packet=environment.housekeeping_packet,
            counter_item=environment.command_counter_item,
            wait_seconds=min(max(command_wait, 0.1), 1.0),
            telemetry_timeout=telemetry_timeout,
        )
        for _ in range(commands)
    ]


def _read_transport_observations(path: Path, transport: str) -> list[dict[str, object]]:
    if not path.exists():
        return []
    observations: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get("transport") == transport:
            observations.append(item)
    return observations


def _summarize_cryptographic_boundary_packets(
    source_packets: list[dict[str, object]], destination_packets: list[dict[str, object]]
) -> dict[str, object]:
    source_payloads = [item for item in source_packets if int(item.get("length", 0) or 0) > 0]
    destination_payloads = [item for item in destination_packets if int(item.get("length", 0) or 0) > 0]
    source_hashes = {str(item["payload_sha256"]) for item in source_payloads if item.get("payload_sha256")}
    destination_hashes = {str(item["payload_sha256"]) for item in destination_payloads if item.get("payload_sha256")}
    complete_ccsds = [
        item
        for item in [*source_payloads, *destination_payloads]
        if bool(item.get("ccsds_complete_packet"))
    ]
    return {
        "transport": "tcp",
        "source_segments": len(source_packets),
        "destination_segments": len(destination_packets),
        "source_payload_segments": len(source_payloads),
        "destination_payload_segments": len(destination_payloads),
        "source_payload_hashes": sorted(source_hashes),
        "destination_payload_hashes": sorted(destination_hashes),
        "matching_payload_hashes": sorted(source_hashes & destination_hashes),
        "complete_ccsds_segments": len(complete_ccsds),
        "complete_ccsds_evidence": complete_ccsds[:8],
    }


def _write_cryptographic_boundary_summary(
    path: Path,
    score: LiveScore,
    boundary_path: CryptographicBoundaryPath,
    packet_summary: dict[str, object],
) -> None:
    text = f"""# Cryptographic-Boundary RF Link Summary

- Result: `{'PASS' if score.passed else 'FAIL'}`
- Attack effect: `{score.attack_effect}`
- Threat model: `{score.threat_model}`
- Protected path: `{boundary_path.source_container}:{boundary_path.source_interface} -> {boundary_path.destination_container}:{boundary_path.destination_interface}:{boundary_path.destination_port}`
- Source payload TCP segments: `{packet_summary['source_payload_segments']}`
- Destination payload TCP segments: `{packet_summary['destination_payload_segments']}`
- Matching payload hashes: `{len(packet_summary['matching_payload_hashes'])}`
- Complete plaintext CCSDS segments: `{packet_summary['complete_ccsds_segments']}`

The score and attack-effect fields define the scenario-specific result. For RF001, a PASS means passive observation exposed complete plaintext CCSDS data; a FAIL with protected frames observed means passive observation was blocked by the boundary.
"""
    path.write_text(text, encoding="utf-8")


def _run_direction_cases(
    *,
    direction: str,
    scenarios: list[Scenario],
    args: argparse.Namespace,
    environment: LinkEnvironment,
    run_root: Path,
    radio_session: RadioDownlinkSession | None = None,
    debug_session: DebugDownlinkSession | None = None,
    uplink_session: UplinkInterceptionSession | None = None,
) -> list[LiveScore]:
    scores: list[LiveScore] = []
    for scenario in scenarios:
        commands = args.commands if args.commands is not None else (
            DEFAULT_DOWNLINK_STIMULI.get(scenario.id, 3)
            if direction == "downlink"
            else DEFAULT_COMMANDS.get(scenario.id, 1)
        )
        score = _run_live_scenario(
            scenario=scenario,
            direction=direction,
            environment=environment,
            run_root=run_root,
            image=args.image,
            listen_port=args.listen_port,
            commands=commands,
            command_wait=args.command_wait,
            telemetry_timeout=args.telemetry_timeout,
            duration=args.duration,
            radio_session=radio_session,
            debug_session=debug_session,
            uplink_session=uplink_session,
        )
        scores.append(score)
        print()
        print(f"{scenario.id} [{direction}]: {'PASS' if score.passed else 'FAIL'}")
        _print_scenario_result(score)
        if args.health_each:
            health = _run_health_check(environment, args.command_wait, args.telemetry_timeout)
            _append_json(run_root / "health_checks.jsonl", {"direction": direction, **health.raw})
            print(f"health after {scenario.id} [{direction}]: {'OK' if health.ok and (health.counter_delta or 0) > 0 else 'NOT CONFIRMED'}")
    return scores


@contextmanager
def _managed_uplink_interception_session(
    *,
    environment: LinkEnvironment,
    owner: str,
    image: str,
    listen_port: int,
    command_wait: float,
    telemetry_timeout: float,
    evidence_path: Path,
    run_root: Path,
) -> Iterator[UplinkInterceptionSession]:
    """Establish one marked OUTPUT-DNAT flow before the command cases begin."""
    session = UplinkInterceptionSession(
        owner=owner,
        link=environment.link,
        target=environment.target,
        interface=environment.cosmos_interface,
        listen_port=listen_port,
    )
    neutral_scenario = load_scenario(PROJECT_ROOT / "security_suites" / "rf_link" / "scenarios" / SCENARIO_FILES["RF-LINK-001"])
    neutral_dir = run_root / "uplink_interception_transport"
    neutral_dir.mkdir(parents=True, exist_ok=True)
    neutral_log = neutral_dir / "preflight_proxy.jsonl"
    neutral_stdout = neutral_dir / "preflight_proxy_stdout.log"
    neutral_name = "cfs-benchmark-uplink-preflight-relay"
    neutral_proxy: subprocess.Popen | None = None

    with _cosmos_output_dnat(
        image=image,
        cosmos_pid=environment.cosmos_pid,
        target_ip=environment.target_ip,
        target_port=environment.target_port,
        proxy_host="127.0.0.1",
        listen_port=listen_port,
        socket_mark=PROXY_SOCKET_MARK,
        evidence_path=neutral_dir / "dnat_evidence.json",
    ):
        try:
            neutral_proxy = _start_proxy(
                image=image,
                scenario=neutral_scenario,
                environment=environment,
                listen_port=listen_port,
                duration=max(telemetry_timeout + 15.0, 30.0),
                proxy_log=neutral_log,
                stdout_log=neutral_stdout,
                cosmos_netns=True,
                socket_mark=PROXY_SOCKET_MARK,
                container_name=neutral_name,
            )
            _wait_for_proxy_socket(neutral_log, timeout=20.0)
            fsw_container = _resolve_container_name("nos-fsw")
            fsw_log_since = time.time()
            preflight = send_noop_and_read_counter(
                container=environment.cosmos_container,
                target=environment.cosmos_target,
                command=environment.noop_command,
                housekeeping_packet=environment.housekeeping_packet,
                counter_item=environment.command_counter_item,
                wait_seconds=min(max(command_wait, 0.1), 1.0),
                telemetry_timeout=telemetry_timeout,
            )
            forwarded = _count_proxy_events(neutral_log, "packet_forwarded")
            system_response = _read_system_response(fsw_container, fsw_log_since)
            execution_confirmed = (preflight.counter_delta or 0) > 0 or int(system_response["executed_noop_count"]) > 0
            session.preflight = {
                "command": preflight.raw,
                "proxy_forwarded_packets": forwarded,
                "system_response": system_response,
                "execution_confirmed": execution_confirmed,
            }
            session.ready = preflight.ok and forwarded > 0 and execution_confirmed
            _write_json(neutral_dir / "preflight.json", session.preflight)
            _stop_proxy_process(neutral_proxy, neutral_name, timeout=5.0)
            yield session
        finally:
            if neutral_proxy is not None:
                _stop_proxy_process(neutral_proxy, neutral_name, timeout=5.0)
            _write_json(evidence_path, session.snapshot())
            print(
                "uplink interception session: "
                f"owner={session.owner}, ready={session.ready}, "
                f"interface={session.interface}, target={session.target}"
            )


@contextmanager
def _managed_radio_downlink_transport(
    *,
    environment: LinkEnvironment,
    owner: str,
    ready_timeout: float,
    evidence_path: Path,
    image: str,
    listen_port: int,
    run_root: Path,
    intercept_cosmos_downlink: bool = True,
) -> Iterator[RadioDownlinkSession]:
    """Keep one RADIO interception flow alive across readiness and every case.

    UDP DNAT is selected only for a connection's first packet.  The neutral
    observer is therefore started before the required RADIO readiness packet,
    then replaced by the case-specific proxy on the same local port.
    """
    session = RadioDownlinkSession(
        cosmos_container=environment.cosmos_container,
        owner=owner,
        ready_timeout_seconds=ready_timeout,
        radio_service=environment.radio_downlink_service,
        radio_service_port=environment.radio_downlink_service_port,
        radio_interface=environment.radio_downlink_interface,
        radio_cosmos_port=environment.radio_downlink_cosmos_port,
    )
    if not intercept_cosmos_downlink:
        try:
            session.open()
            yield session
        finally:
            session.close()
            _write_json(evidence_path, session.snapshot())
            print(
                "RADIO downlink session: "
                f"enabled={session.enabled}, ready={session.ready}, disabled={session.disabled}, "
                f"interface={session.radio_interface}:{session.radio_cosmos_port} "
                f"network={environment.downlink_destination_interface}"
            )
            if session.cleanup_warning:
                print(f"RADIO downlink cleanup warning: {session.cleanup_warning}")
        return

    neutral_scenario = load_scenario(PROJECT_ROOT / "security_suites" / "rf_link" / "scenarios" / SCENARIO_FILES["RF-LINK-001"])
    neutral_dir = run_root / "radio_downlink_transport"
    neutral_log = neutral_dir / "readiness_proxy.jsonl"
    neutral_stdout = neutral_dir / "readiness_proxy_stdout.log"
    neutral_dir.mkdir(parents=True, exist_ok=True)
    neutral_proxy: subprocess.Popen | None = None

    with _cosmos_prerouting_dnat(
        image=image,
        cosmos_pid=environment.cosmos_pid,
        target_ip=environment.cosmos_ip,
        target_port=environment.downlink_destination_port,
        proxy_host=environment.cosmos_ip,
        listen_port=listen_port,
        socket_mark=PROXY_SOCKET_MARK,
        evidence_path=neutral_dir / "dnat_evidence.json",
    ):
        try:
            neutral_proxy = _start_downlink_proxy(
                image=image,
                scenario=neutral_scenario,
                environment=environment,
                listen_port=listen_port,
                duration=max(ready_timeout + 15.0, 30.0),
                proxy_log=neutral_log,
                stdout_log=neutral_stdout,
                cosmos_netns=True,
                socket_mark=PROXY_SOCKET_MARK,
                listen_host="0.0.0.0",
                container_name="cfs-benchmark-radio-readiness-relay",
            )
            _wait_for_proxy_socket(neutral_log, timeout=20.0)
            session.open()
            if neutral_proxy.poll() is None:
                subprocess.run(
                    ["docker", "stop", "-t", "1", "cfs-benchmark-radio-readiness-relay"],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            _wait_or_terminate(neutral_proxy, timeout=3.0)
            yield session
        finally:
            if neutral_proxy is not None and neutral_proxy.poll() is None:
                subprocess.run(
                    ["docker", "stop", "-t", "1", "cfs-benchmark-radio-readiness-relay"],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                _wait_or_terminate(neutral_proxy, timeout=3.0)
            session.close()
            _write_json(evidence_path, session.snapshot())
            print(
                "RADIO downlink session: "
                f"enabled={session.enabled}, ready={session.ready}, disabled={session.disabled}, "
                f"interface={session.radio_interface}:{session.radio_cosmos_port} "
                f"network={environment.downlink_destination_interface}"
            )
            if session.cleanup_warning:
                print(f"RADIO downlink cleanup warning: {session.cleanup_warning}")


@contextmanager
def _managed_debug_downlink_transport(
    *,
    environment: LinkEnvironment,
    owner: str,
    ready_timeout: float,
    evidence_path: Path,
    image: str,
    listen_port: int,
    run_root: Path,
) -> Iterator[DebugDownlinkSession]:
    """Intercept the already-enabled DEBUG downlink without changing TO routing."""
    session = DebugDownlinkSession(
        cosmos_container=environment.cosmos_container,
        owner=owner,
        ready_timeout_seconds=ready_timeout,
        debug_interface=environment.cosmos_interface,
        debug_cosmos_port=environment.downlink_destination_port,
    )
    neutral_scenario = load_scenario(PROJECT_ROOT / "security_suites" / "rf_link" / "scenarios" / SCENARIO_FILES["RF-LINK-001"])
    neutral_dir = run_root / "debug_downlink_transport"
    neutral_dir.mkdir(parents=True, exist_ok=True)
    neutral_log = neutral_dir / "readiness_proxy.jsonl"
    neutral_stdout = neutral_dir / "readiness_proxy_stdout.log"
    neutral_name = "cfs-benchmark-debug-readiness-relay"
    neutral_proxy: subprocess.Popen | None = None

    with _cosmos_prerouting_tproxy(
        image=image,
        cosmos_pid=environment.cosmos_pid,
        target_ip=environment.cosmos_ip,
        target_port=environment.downlink_destination_port,
        proxy_host=environment.cosmos_ip,
        listen_port=listen_port,
        socket_mark=PROXY_SOCKET_MARK,
        evidence_path=neutral_dir / "dnat_evidence.json",
    ):
        try:
            neutral_proxy = _start_downlink_proxy(
                image=image,
                scenario=neutral_scenario,
                environment=environment,
                listen_port=listen_port,
                duration=max(ready_timeout + 15.0, 30.0),
                proxy_log=neutral_log,
                stdout_log=neutral_stdout,
                cosmos_netns=True,
                socket_mark=PROXY_SOCKET_MARK,
                listen_host="0.0.0.0",
                transparent_listen=True,
                container_name=neutral_name,
            )
            _wait_for_proxy_socket(neutral_log, timeout=20.0)
            session.open()
            _stop_proxy_process(neutral_proxy, neutral_name, timeout=5.0)
            yield session
        finally:
            if neutral_proxy is not None:
                _stop_proxy_process(neutral_proxy, neutral_name, timeout=5.0)
            session.close()
            _write_json(evidence_path, session.snapshot())
            print(
                "DEBUG downlink session: "
                f"ready={session.ready}, interface={session.debug_interface}:{session.debug_cosmos_port} "
                f"network={environment.downlink_destination_interface}"
            )


def _run_live_scenario(
    *,
    scenario: Scenario,
    direction: str,
    environment: LinkEnvironment,
    run_root: Path,
    image: str,
    listen_port: int,
    commands: int,
    command_wait: float,
    telemetry_timeout: float,
    duration: float,
    radio_session: RadioDownlinkSession | None = None,
    debug_session: DebugDownlinkSession | None = None,
    uplink_session: UplinkInterceptionSession | None = None,
) -> LiveScore:
    if direction == "downlink":
        downlink_session = radio_session or debug_session
        if downlink_session is None:
            raise RuntimeError("downlink case requires an outer link-specific downlink session")
        if not downlink_session.ready:
            score = _downlink_not_ready_score(scenario, downlink_session)
            scenario_dir = run_root / scenario.id / "downlink"
            scenario_dir.mkdir(parents=True, exist_ok=True)
            write_environment(scenario_dir / "environment.json", environment)
            _write_json(scenario_dir / "downlink_session.json", downlink_session.snapshot())
            _write_json(scenario_dir / "score.json", score.to_dict())
            return score
        return _run_live_downlink_scenario(
            scenario=scenario,
            environment=environment,
            run_root=run_root,
            image=image,
            listen_port=listen_port + 1,
            commands=commands,
            command_wait=command_wait,
            telemetry_timeout=telemetry_timeout,
            duration=duration,
            downlink_session=downlink_session,
        )
    if uplink_session is None:
        raise RuntimeError("uplink case requires an outer UplinkInterceptionSession")
    if not uplink_session.ready:
        return _uplink_not_ready_score(scenario, uplink_session)
    return _run_live_uplink_scenario(
        scenario=scenario,
        environment=environment,
        run_root=run_root,
        image=image,
        listen_port=listen_port,
        commands=commands,
        command_wait=command_wait,
        telemetry_timeout=telemetry_timeout,
        duration=duration,
        uplink_session=uplink_session,
    )


def _run_live_uplink_scenario(
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
    uplink_session: UplinkInterceptionSession,
) -> LiveScore:
    if scenario.id not in COMMAND_DRIVEN_SCENARIOS and scenario.id not in ACTIVE_SCENARIOS:
        raise SystemExit(f"{scenario.id} is not supported by the live runner yet.")

    scenario_dir = run_root / scenario.id / "uplink"
    scenario_dir.mkdir(parents=True, exist_ok=True)
    write_environment(scenario_dir / "environment.json", environment)
    _write_json(scenario_dir / "uplink_interception_session.json", uplink_session.snapshot())

    proxy_log = scenario_dir / "attack_internal.jsonl"
    proxy_stdout = scenario_dir / "attack_stdout.log"
    pcap_path = scenario_dir / "packets.pcap"
    observation_path = scenario_dir / "packet_observations.jsonl"
    proxy_pcap_path = scenario_dir / "proxy_packets.pcap"
    proxy_observation_path = scenario_dir / "proxy_packet_observations.jsonl"
    receiver_pcap_path = scenario_dir / "receiver_packets.pcap"
    receiver_observation_path = scenario_dir / "receiver_packet_observations.jsonl"
    command_log = scenario_dir / "cosmos_commands.jsonl"
    interface_log = scenario_dir / "cosmos_interface.jsonl"
    system_response_path = scenario_dir / "system_response.json"
    dnat_evidence_path = scenario_dir / "dnat_evidence.json"
    target_counter_path = scenario_dir / "target_counter_evidence.json"

    print()
    print(f"scenario: {scenario.id} {scenario.name}")
    print(f"commands: {commands if scenario.id in COMMAND_DRIVEN_SCENARIOS else 0}")
    effective_duration = _scenario_duration(scenario, duration, commands, command_wait, telemetry_timeout)
    target_container = environment.downlink_source_container
    fsw_container = _resolve_container_name("nos-fsw")
    fsw_log_since = time.time()

    capture_duration = _capture_duration(scenario, effective_duration, commands, command_wait, telemetry_timeout)
    packet_capture_enabled = True
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
    if scenario.id == "RF-LINK-001":
        captures.append(
            TcpdumpCapture(
                interface="eth0",
                pcap_path=receiver_pcap_path,
                observation_path=receiver_observation_path,
                ports=[environment.target_port],
                image=image,
                mount_root=PROJECT_ROOT,
                duration=capture_duration,
                network_container=target_container,
            )
        )

    with _capture_contexts(captures):
        # The outer session owns the one OUTPUT-DNAT rule for every case.
        redirect_context = _null_context()
        with redirect_context:
            target_counter_context = (
                _target_input_counter(
                    image=image,
                    target_container=target_container,
                    target_port=environment.target_port,
                    evidence_path=target_counter_path,
                )
                if scenario.id in ACTIVE_SCENARIOS or scenario.id == "RF-LINK-001"
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
                        sent_results = _send_scenario_commands(
                            scenario=scenario,
                            environment=environment,
                            commands=commands,
                            command_wait=command_wait,
                            telemetry_timeout=telemetry_timeout,
                            observation_path=proxy_observation_path if packet_capture_enabled else None,
                            listen_port=listen_port,
                            proxy_log=proxy_log,
                        )
                        for result in sent_results:
                            command_results.append(result)
                            _append_json(command_log, result.raw)
                finally:
                    if scenario.id in COMMAND_DRIVEN_SCENARIOS and proxy.poll() is None:
                        _stop_proxy_process(proxy, _proxy_container_name(scenario), timeout=5.0)
                    else:
                        _wait_or_terminate(proxy, timeout=max(effective_duration + 2, 3))

    observations = read_udp_observations(pcap_path, [environment.target_port], observation_path)
    if scenario.id in COMMAND_DRIVEN_SCENARIOS:
        observations.extend(read_udp_observations(proxy_pcap_path, [listen_port], proxy_observation_path))
    if scenario.id == "RF-LINK-001":
        observations.extend(read_udp_observations(receiver_pcap_path, [environment.target_port], receiver_observation_path))
    system_response = _read_system_response(fsw_container, fsw_log_since)
    packet_summary = summarize_link_packets(
        observations,
        listen_port=listen_port,
        target_ip=environment.target_ip,
        target_port=environment.target_port,
    )
    dnat_evidence = _read_json(dnat_evidence_path) if dnat_evidence_path.exists() else {}
    dnat_packets = int(dnat_evidence.get("packets", 0) or 0)
    proxy_received_packets = _count_proxy_events(proxy_log, "packet_received")
    proxy_forwarded_packets = _count_proxy_events(proxy_log, "packet_forwarded")
    target_counter = _read_json(target_counter_path) if target_counter_path.exists() else {}
    target_counter_packets = int(target_counter.get("packets", 0) or 0)
    packet_summary["packets_redirected_by_dnat"] = dnat_packets
    packet_summary["proxy_received_packets"] = proxy_received_packets
    packet_summary["proxy_forwarded_packets"] = proxy_forwarded_packets
    packet_summary["proxy_entry_packets"] = max(int(packet_summary["packets_to_proxy"]), dnat_packets, proxy_received_packets)
    packet_summary["packets_seen_by_target_counter"] = target_counter_packets
    packet_summary["target_entry_packets"] = max(int(packet_summary["packets_to_target"]), target_counter_packets)
    proxy_delays = _proxy_forward_delays(proxy_log)
    if proxy_delays:
        packet_summary["forward_delays_seconds"] = proxy_delays
        packet_summary["max_forward_delay_seconds"] = max(proxy_delays)
    packet_summary["proxy_reorder_windows"] = _count_proxy_events(proxy_log, "packets_reordered")
    packet_summary["actual_reorder_observed"] = _has_actual_reorder(proxy_log)
    score = _score_scenario(scenario, command_results, packet_summary, system_response)
    score.evidence["uplink_interception_session"] = uplink_session.snapshot()
    _write_json(scenario_dir / "packet_summary.json", packet_summary)
    _write_json(system_response_path, system_response)
    _write_json(scenario_dir / "score.json", score.to_dict())
    _write_scenario_summary(scenario_dir / "summary.md", scenario, environment, score, packet_summary)
    return score


def _run_live_downlink_scenario(
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
    downlink_session: RadioDownlinkSession | DebugDownlinkSession,
) -> LiveScore:
    scenario_dir = run_root / scenario.id / "downlink"
    scenario_dir.mkdir(parents=True, exist_ok=True)
    write_environment(scenario_dir / "environment.json", environment)
    _write_json(scenario_dir / "downlink_session.json", downlink_session.snapshot())

    proxy_log = scenario_dir / "attack_internal.jsonl"
    proxy_stdout = scenario_dir / "attack_stdout.log"
    pcap_path = scenario_dir / "packets.pcap"
    observation_path = scenario_dir / "packet_observations.jsonl"
    stimulus_log = scenario_dir / "telemetry_stimulus.jsonl"
    dnat_evidence_path = scenario_dir / "dnat_evidence.json"
    receiver_counter_path = scenario_dir / "receiver_counter_evidence.json"

    effective_duration = _scenario_duration(scenario, duration, commands, command_wait, telemetry_timeout)
    proxy_duration = max(
        effective_duration,
        _active_attack_duration(scenario),
        _downlink_stimulus_window(commands, command_wait, telemetry_timeout),
    )
    capture_duration = _capture_duration(scenario, proxy_duration, commands, command_wait, telemetry_timeout)
    captures = [
        TcpdumpCapture(
            interface=environment.downlink_destination_interface,
            pcap_path=pcap_path,
            observation_path=observation_path,
            ports=[environment.downlink_destination_port, listen_port],
            image=image,
            mount_root=PROJECT_ROOT,
            duration=capture_duration,
            network_container=environment.cosmos_container,
        ),
        TcpdumpCapture(
            interface="lo",
            pcap_path=scenario_dir / "forwarded_packets.pcap",
            observation_path=scenario_dir / "forwarded_packet_observations.jsonl",
            ports=[environment.downlink_destination_port, listen_port],
            image=image,
            mount_root=PROJECT_ROOT,
            duration=capture_duration,
            network_container=environment.cosmos_container,
        ),
    ]

    print()
    print(f"scenario: {scenario.id} {scenario.name} [downlink]")
    expected_packet = "CFS_RADIO SC_HKTLM" if environment.link == "radio" else "CFS SC_HKTLM"
    print(f"stimulus: DEBUG CFS SC_SEND_HK -> {environment.link.upper()} {expected_packet}")
    print(
        f"downlink: {environment.downlink_source_name} "
        f"({environment.downlink_source_container}) -> {environment.downlink_destination}"
    )

    with _capture_contexts(captures):
        with _target_input_counter(
            image=image,
            target_container=environment.cosmos_container,
            target_port=environment.downlink_destination_port,
            evidence_path=receiver_counter_path,
            packet_mark=PROXY_SOCKET_MARK if environment.link == "debug" else None,
        ):
            stimulus_results: list[CosmosCommandResult] = []
            proxy = _start_downlink_proxy(
                image=image,
                scenario=scenario,
                environment=environment,
                listen_port=listen_port,
                duration=proxy_duration,
                proxy_log=proxy_log,
                stdout_log=proxy_stdout,
                cosmos_netns=True,
                socket_mark=PROXY_SOCKET_MARK,
                listen_host="0.0.0.0",
                transparent_listen=environment.link == "debug",
            )
            try:
                _wait_for_proxy_socket(proxy_log, timeout=20.0)
                attack_started = time.monotonic()
                stimulus_results = _send_downlink_stimuli(
                    environment=environment,
                    commands=commands,
                    command_wait=command_wait,
                    telemetry_timeout=telemetry_timeout,
                )
                for result in stimulus_results:
                    _append_json(stimulus_log, result.raw)
                remaining_active_time = _active_attack_duration(scenario) - (time.monotonic() - attack_started)
                if remaining_active_time > 0:
                    time.sleep(remaining_active_time)
            finally:
                if proxy.poll() is None:
                    subprocess.run(
                        ["docker", "kill", "--signal=SIGINT", _proxy_container_name(scenario, "downlink")],
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                _wait_or_terminate(proxy, timeout=5)

    observations = read_udp_observations(
        pcap_path,
        [environment.downlink_destination_port, listen_port],
        observation_path,
    )
    observations.extend(
        read_udp_observations(
            scenario_dir / "forwarded_packets.pcap",
            [environment.downlink_destination_port, listen_port],
            scenario_dir / "forwarded_packet_observations.jsonl",
        )
    )
    packet_summary = summarize_link_packets(
        observations,
        listen_port=listen_port,
        target_ip=environment.cosmos_ip,
        target_port=environment.downlink_destination_port,
    )
    dnat_evidence = _read_json(dnat_evidence_path) if dnat_evidence_path.exists() else {}
    receiver_counter = _read_json(receiver_counter_path) if receiver_counter_path.exists() else {}
    packet_summary["packets_redirected_by_dnat"] = int(dnat_evidence.get("packets", 0) or 0)
    packet_summary["proxy_received_packets"] = _count_proxy_events(proxy_log, "packet_received")
    packet_summary["proxy_forwarded_packets"] = _count_proxy_events(proxy_log, "packet_forwarded")
    packet_summary["proxy_flooded_packets"] = _count_proxy_events(proxy_log, "packet_flooded")
    packet_summary["proxy_fabricated_packets"] = _count_proxy_events(proxy_log, "packet_fabricated")
    packet_summary["proxy_bit_flipped_packets"] = _count_proxy_events(proxy_log, "packet_bit_flipped")
    packet_summary["proxy_entry_packets"] = max(
        int(packet_summary["packets_to_proxy"]),
        int(packet_summary["packets_redirected_by_dnat"]),
        int(packet_summary["proxy_received_packets"]),
    )
    packet_summary["packets_seen_by_receiver_counter"] = int(receiver_counter.get("packets", 0) or 0)
    # The physical-interface capture sees packets before interception, so it
    # includes packets that the proxy subsequently drops. DEBUG TPROXY also
    # routes those original packets through INPUT; therefore its counter only
    # counts proxy-forwarded packets marked with PROXY_SOCKET_MARK.
    packet_summary["receiver_entry_packets"] = int(packet_summary["packets_seen_by_receiver_counter"])
    proxy_hashes = _proxy_payload_hashes(proxy_log, "packet_received")
    forwarded_hashes = _proxy_payload_hashes(proxy_log, "packet_forwarded")
    target_hashes = set(packet_summary.get("target_payload_hashes", []))
    packet_summary["proxy_payload_hashes"] = sorted(proxy_hashes)
    packet_summary["forwarded_payload_hashes"] = sorted(forwarded_hashes)
    packet_summary["matching_payload_hashes"] = sorted(proxy_hashes & target_hashes)
    packet_summary["matching_forwarded_payload_hashes"] = sorted(forwarded_hashes & target_hashes)
    proxy_delays = _proxy_forward_delays(proxy_log)
    if proxy_delays:
        packet_summary["forward_delays_seconds"] = proxy_delays
        packet_summary["max_forward_delay_seconds"] = max(proxy_delays)

    score = _score_downlink_scenario(scenario, stimulus_results, packet_summary, downlink_session)
    _write_json(scenario_dir / "packet_summary.json", packet_summary)
    _write_json(scenario_dir / "score.json", score.to_dict())
    _write_downlink_summary(scenario_dir / "summary.md", scenario, environment, score, packet_summary)
    return score


def _downlink_not_ready_score(
    scenario: Scenario,
    downlink_session: RadioDownlinkSession | DebugDownlinkSession,
) -> LiveScore:
    return LiveScore(
        scenario_id=scenario.id,
        direction="downlink",
        passed=False,
        evidence={
            "downlink_session": downlink_session.snapshot(),
            "packet_summary": {},
            "telemetry_stimulus_requests": 0,
            "successful_telemetry_responses": 0,
        },
        notes=["Selected downlink link was not ready; no case traffic was started."],
    )


def _uplink_not_ready_score(scenario: Scenario, uplink_session: UplinkInterceptionSession) -> LiveScore:
    return LiveScore(
        scenario_id=scenario.id,
        direction="uplink",
        passed=False,
        evidence={
            "uplink_interception_session": uplink_session.snapshot(),
            "packet_summary": {},
        },
        notes=["Uplink interception preflight was not confirmed; no case traffic was started."],
    )


def _send_downlink_stimuli(
    *,
    environment: LinkEnvironment,
    commands: int,
    command_wait: float,
    telemetry_timeout: float,
) -> list[CosmosCommandResult]:
    results: list[CosmosCommandResult] = []
    for _ in range(commands):
        if environment.link == "debug":
            raw = send_debug_housekeeping(
                container=environment.cosmos_container,
                timeout_seconds=telemetry_timeout,
            )
            raw["stimulus"] = "debug_housekeeping_request"
            results.append(
                CosmosCommandResult(
                    ok=bool(raw.get("ok")),
                    target="CFS",
                    command="SC_SEND_HK",
                    counter_before=0,
                    counter_after=1 if raw.get("ok") else 0,
                    raw=raw,
                )
            )
            continue
        if environment.link == "radio":
            raw = send_radio_housekeeping(
                container=environment.cosmos_container,
                timeout_seconds=telemetry_timeout,
                radio_interface=environment.radio_downlink_interface,
                radio_cosmos_port=environment.radio_downlink_cosmos_port,
            )
            raw["stimulus"] = "radio_housekeeping_request"
            results.append(
                CosmosCommandResult(
                    ok=bool(raw.get("ok")),
                    target="CFS_RADIO",
                    command="SC_SEND_HK",
                    counter_before=0,
                    counter_after=1 if raw.get("ok") else 0,
                    raw=raw,
                )
            )
            continue
        result = send_noop_and_read_counter(
            container=environment.cosmos_container,
            target=environment.telemetry_target,
            command=environment.telemetry_request_command,
            housekeeping_packet=environment.telemetry_packet,
            counter_item=environment.telemetry_freshness_item,
            wait_seconds=min(max(command_wait, 0.1), 1.0),
            telemetry_timeout=telemetry_timeout,
        )
        result.raw.setdefault("stimulus", "telemetry_request")
        results.append(result)
    return results


def _active_attack_duration(scenario: Scenario) -> float:
    if scenario.id == "RF-LINK-006":
        return float(scenario.attack.get("flood_duration_seconds", 0))
    if scenario.id == "RF-LINK-007":
        return int(scenario.attack.get("count", 0)) * float(scenario.attack.get("interval_ms", 0)) / 1000.0
    return 0.0


def _downlink_stimulus_window(commands: int, command_wait: float, telemetry_timeout: float) -> float:
    per_request = min(max(command_wait, 0.1), 1.0) + max(telemetry_timeout, 0.0)
    return commands * per_request + 4.0


def _score_downlink_scenario(
    scenario: Scenario,
    stimulus_results: list[CosmosCommandResult],
    packet_summary: dict[str, object],
    downlink_session: RadioDownlinkSession | DebugDownlinkSession,
) -> LiveScore:
    responses = _successful_command_count(stimulus_results)
    requested = _sent_command_count(stimulus_results)
    proxy_entry = int(packet_summary["proxy_entry_packets"])
    receiver_entry = int(packet_summary["receiver_entry_packets"])
    forwarded = int(packet_summary["proxy_forwarded_packets"])
    flooded = int(packet_summary["proxy_flooded_packets"])
    fabricated = int(packet_summary["proxy_fabricated_packets"])
    bit_flipped = int(packet_summary.get("proxy_bit_flipped_packets", 0))
    max_delay = packet_summary.get("max_forward_delay_seconds")
    passed = False
    notes: list[str] = []

    if scenario.id == "RF-LINK-001":
        passed = (
            proxy_entry > 0
            and receiver_entry > 0
            and responses > 0
            and bool(packet_summary.get("matching_payload_hashes", []))
        )
    elif scenario.id == "RF-LINK-002":
        passed = proxy_entry > receiver_entry and responses < requested
    elif scenario.id == "RF-LINK-003":
        expected_delay = float(scenario.attack.get("delay_ms", 1000)) / 1000.0
        passed = receiver_entry > 0 and max_delay is not None and float(max_delay) >= expected_delay * 0.8
    elif scenario.id == "RF-LINK-004":
        passed = proxy_entry > 0 and forwarded > proxy_entry and receiver_entry > proxy_entry
    elif scenario.id == "RF-LINK-005":
        passed = (
            proxy_entry > 0
            and receiver_entry > 0
            and bit_flipped > 0
            and bool(packet_summary.get("matching_forwarded_payload_hashes", []))
        )
    elif scenario.id == "RF-LINK-006":
        expected_min = max(5, int(float(scenario.attack.get("rate_per_second", 20)) * min(float(scenario.attack.get("flood_duration_seconds", 10)), 5) * 0.5))
        passed = flooded >= expected_min and receiver_entry >= expected_min
    elif scenario.id == "RF-LINK-007":
        expected_count = int(scenario.attack.get("count", 1))
        passed = fabricated >= expected_count and receiver_entry >= expected_count
    elif scenario.id == "RF-LINK-008":
        window_size = int(scenario.attack.get("window_size", 4))
        passed = proxy_entry >= window_size and forwarded >= proxy_entry and receiver_entry >= proxy_entry

    if passed:
        session_snapshot = downlink_session.snapshot()
        link_interface = session_snapshot.get("radio_interface", session_snapshot.get("debug_interface"))
        notes.append(
            f"Downlink {scenario.attack_type} effect was observed on the selected "
            f"{link_interface}-to-COSMOS telemetry path."
        )
    else:
        notes.append(
            "Downlink effect was not established from the telemetry stimulus, proxy evidence, and COSMOS receiver evidence."
        )

    return LiveScore(
        scenario_id=scenario.id,
        direction="downlink",
        passed=passed,
        evidence={
            "downlink_session": downlink_session.snapshot(),
            "telemetry_stimulus_requests": requested,
            "successful_telemetry_responses": responses,
            "stimulus_results": [result.raw for result in stimulus_results],
            "packet_summary": packet_summary,
        },
        notes=notes,
    )


def _select_scenarios(scenario_arg: str | None, run_all: bool) -> list[Scenario]:
    if run_all:
        by_id = {scenario.id: scenario for scenario in load_scenarios(PROJECT_ROOT / "security_suites" / "rf_link" / "scenarios")}
        return [by_id[scenario_id] for scenario_id in LIVE_RUN_ORDER if scenario_id in by_id]
    if not scenario_arg:
        scenario_arg = "RF-LINK-001"
    if scenario_arg in SCENARIO_FILES:
        return [load_scenario(PROJECT_ROOT / "security_suites" / "rf_link" / "scenarios" / SCENARIO_FILES[scenario_arg])]
    return [load_scenario(PROJECT_ROOT / scenario_arg)]


def _print_scenario_result(score: LiveScore) -> None:
    evidence = score.evidence
    packet_summary = evidence.get("packet_summary", {})
    system_response = evidence.get("system_response", {})
    if score.direction == "downlink":
        session = evidence.get("downlink_session", {})
        print(
            "  evidence: "
            f"telemetry={evidence.get('successful_telemetry_responses', 0)}/"
            f"{evidence.get('telemetry_stimulus_requests', 0)}"
        )
        print(
            "  downlink session: "
            f"ready={session.get('radio_downlink_ready', session.get('debug_downlink_ready'))}, "
            f"interface={session.get('radio_interface', session.get('debug_interface'))}:"
            f"{session.get('radio_cosmos_port', session.get('debug_cosmos_port'))}"
        )
        print(
            "  traffic: "
            f"intercept={session.get('debug_intercept_method', 'DNAT')}, "
            f"proxy_entry={packet_summary.get('proxy_entry_packets', 0)}, "
            f"proxy_forwarded={packet_summary.get('proxy_forwarded_packets', 0)}, "
            f"receiver_entry={packet_summary.get('receiver_entry_packets', 0)}"
        )
        for note in score.notes[:2]:
            print(f"  note: {note}")
        return
    print(
        "  evidence: "
        f"system={evidence.get('successful_system_responses', 0)}/{evidence.get('total_cosmos_commands', 0)}, "
        f"cosmos_counter={evidence.get('successful_cosmos_commands', 0)}, "
        f"cfs_noop={evidence.get('executed_noop_log_count', 0)}, "
        f"cfs_errors={evidence.get('error_event_count', 0)}"
    )
    print(
        "  traffic: "
        "dnat=session-managed, "
        f"proxy_entry={packet_summary.get('proxy_entry_packets', packet_summary.get('packets_to_proxy', 0))}, "
        f"proxy_forwarded={packet_summary.get('proxy_forwarded_packets', 0)}, "
        f"target_entry={packet_summary.get('target_entry_packets', packet_summary.get('packets_to_target', 0))}"
    )
    if score.scenario_id == "RF-LINK-003":
        print(f"  delay: max_forward={packet_summary.get('max_forward_delay_seconds')}s")
    if score.scenario_id == "RF-LINK-008":
        print(
            "  reorder: "
            f"windows={packet_summary.get('proxy_reorder_windows', 0)}, "
            f"order_changed={packet_summary.get('actual_reorder_observed', False)}"
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


@contextmanager
def _cosmos_prerouting_tproxy(
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
    """Intercept every DEBUG UDP packet without relying on conntrack NAT state."""
    add_policy_rule = _cosmos_namespace_ip_command(
        image=image,
        cosmos_pid=cosmos_pid,
        arguments=[
            "rule",
            "add",
            "priority",
            str(TPROXY_RULE_PRIORITY),
            "fwmark",
            f"{TPROXY_PACKET_MARK}/0xffffffff",
            "lookup",
            str(TPROXY_ROUTING_TABLE),
        ],
    )
    delete_policy_rule = _cosmos_namespace_ip_command(
        image=image,
        cosmos_pid=cosmos_pid,
        arguments=[
            "rule",
            "delete",
            "priority",
            str(TPROXY_RULE_PRIORITY),
            "fwmark",
            f"{TPROXY_PACKET_MARK}/0xffffffff",
            "lookup",
            str(TPROXY_ROUTING_TABLE),
        ],
    )
    add_local_route = _cosmos_namespace_ip_command(
        image=image,
        cosmos_pid=cosmos_pid,
        arguments=["route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", str(TPROXY_ROUTING_TABLE)],
    )
    delete_local_route = _cosmos_namespace_ip_command(
        image=image,
        cosmos_pid=cosmos_pid,
        arguments=["route", "delete", "local", "0.0.0.0/0", "dev", "lo", "table", str(TPROXY_ROUTING_TABLE)],
    )
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
        "mangle",
        "-A",
        "PREROUTING",
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
        "TPROXY",
        "--on-ip",
        proxy_host,
        "--on-port",
        str(listen_port),
        "--tproxy-mark",
        f"{TPROXY_PACKET_MARK}/0xffffffff",
    ]
    delete_rule = add_rule.copy()
    delete_rule[delete_rule.index("-A")] = "-D"
    policy_rule_added = False
    local_route_added = False
    try:
        _run(add_policy_rule)
        policy_rule_added = True
        _run(add_local_route)
        local_route_added = True
        _run(add_rule)
        yield
    finally:
        evidence = _read_tproxy_rule_counter(
            image=image,
            cosmos_pid=cosmos_pid,
            target_ip=target_ip,
            target_port=target_port,
            proxy_host=proxy_host,
            listen_port=listen_port,
            socket_mark=socket_mark,
        )
        subprocess.run(delete_rule, check=False)
        if local_route_added:
            subprocess.run(delete_local_route, check=False)
        if policy_rule_added:
            subprocess.run(delete_policy_rule, check=False)
        evidence["intercept_namespace"] = "cosmos"
        evidence["intercept_chain"] = "PREROUTING"
        evidence["intercept_method"] = "TPROXY"
        evidence["tproxy_packet_mark"] = TPROXY_PACKET_MARK
        evidence["tproxy_routing_table"] = TPROXY_ROUTING_TABLE
        _write_json(evidence_path, evidence)


def _cosmos_namespace_ip_command(*, image: str, cosmos_pid: str, arguments: list[str]) -> list[str]:
    return [
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
        f"--root=/proc/{cosmos_pid}/root",
        "/sbin/ip",
        *arguments,
    ]


def _read_tproxy_rule_counter(
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
            "mangle",
            "-v",
            "-n",
            "-L",
            "PREROUTING",
            "--line-numbers",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    destination_hint = f"{proxy_host}:{listen_port}"
    for line in result.stdout.splitlines():
        if target_ip not in line or destination_hint not in line or f"dpt:{target_port}" not in line:
            continue
        parts = line.split()
        return {
            "ok": True,
            "packets": _safe_int(parts[1] if len(parts) > 1 else None),
            "bytes": _safe_int(parts[2] if len(parts) > 2 else None),
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
def _cosmos_prerouting_dnat(
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
        "PREROUTING",
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
            chain="PREROUTING",
        )
        evidence["intercept_namespace"] = "cosmos"
        evidence["intercept_chain"] = "PREROUTING"
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
    chain: str = "OUTPUT",
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
            chain,
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
    packet_mark: int | None = None,
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
    if packet_mark is not None:
        add_rule.extend(["-m", "mark", "--mark", str(packet_mark)])
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
            packet_mark=packet_mark,
        )
        _write_json(evidence_path, evidence)
        subprocess.run(delete_rule, check=False)


def _read_filter_rule_counter(
    *,
    image: str,
    target_pid: str,
    target_port: int,
    packet_mark: int | None,
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
        if packet_mark is not None and f"0x{packet_mark:x}" not in line:
            continue
        parts = line.split()
        return {
            "ok": True,
            "packets": _safe_int(parts[1] if len(parts) > 1 else None),
            "bytes": _safe_int(parts[2] if len(parts) > 2 else None),
            "line": line.strip(),
            "packet_mark": packet_mark,
        }
    return {
        "ok": False,
        "packets": 0,
        "bytes": 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "packet_mark": packet_mark,
    }


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
    container_name: str | None = None,
) -> subprocess.Popen:
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name or _proxy_container_name(scenario),
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
            "benchmark_engine.rf_link.proxy",
        "--scenario",
        f"security_suites/rf_link/scenarios/{_scenario_filename(scenario)}",
        "--listen",
        f"0.0.0.0:{listen_port}",
        "--target",
        environment.target,
        "--duration",
        str(duration),
        "--log",
        str(proxy_log.relative_to(PROJECT_ROOT)),
        "--traffic-direction",
        "uplink",
        ]
    )
    if socket_mark is not None:
        command.extend(["--socket-mark", str(socket_mark)])
    stdout_log.parent.mkdir(parents=True, exist_ok=True)
    handle = stdout_log.open("w", encoding="utf-8")
    return subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT, text=True)


def _start_downlink_proxy(
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
    listen_host: str | None = None,
    transparent_listen: bool = False,
    container_name: str | None = None,
) -> subprocess.Popen:
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name or _proxy_container_name(scenario, "downlink"),
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
    resolved_listen_host = listen_host or ("127.0.0.1" if cosmos_netns else "0.0.0.0")
    command.extend(
        [
            "python3",
            "-m",
            "benchmark_engine.rf_link.proxy",
            "--scenario",
            f"security_suites/rf_link/scenarios/{_scenario_filename(scenario)}",
            "--listen",
            f"{resolved_listen_host}:{listen_port}",
            "--target",
            environment.downlink_destination,
            "--duration",
            str(duration),
            "--log",
            str(proxy_log.relative_to(PROJECT_ROOT)),
            "--traffic-direction",
            "downlink",
        ]
    )
    if socket_mark is not None:
        command.extend(["--socket-mark", str(socket_mark)])
    if transparent_listen:
        command.append("--transparent-listen")
    stdout_log.parent.mkdir(parents=True, exist_ok=True)
    handle = stdout_log.open("w", encoding="utf-8")
    return subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT, text=True)


def _proxy_container_name(scenario: Scenario, direction: str = "uplink") -> str:
    suffix = "" if direction == "uplink" else f"-{direction}"
    return f"cfs-benchmark-live-{scenario.id.lower()}{suffix}"


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


def _stop_proxy_process(process: subprocess.Popen, container_name: str, timeout: float) -> None:
    if process.poll() is not None:
        return
    subprocess.run(
        ["docker", "kill", "--signal=SIGINT", container_name],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_or_terminate(process, timeout=timeout)


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
    proxy_log: Path | None = None,
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
            proxy_log=proxy_log,
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
    proxy_log: Path | None,
) -> list[CosmosCommandResult]:
    results: list[CosmosCommandResult] = []
    target_packets = int(scenario.attack.get("window_size", commands))
    max_attempts = max(commands + 4, target_packets + 6)
    for index in range(max_attempts):
        received_before = _count_proxy_events(proxy_log, "packet_received") if proxy_log else 0
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
        _wait_for_proxy_event_count(proxy_log, "packet_received", received_before + 1, timeout=max(1.5, command_wait + 1.0))
        if proxy_log and _count_proxy_events(proxy_log, "packet_received") >= target_packets:
            break
        time.sleep(min(max(command_wait, 0.25), 0.75))
    return results


def _wait_for_proxy_event_count(log_path: Path | None, event: str, count: int, timeout: float) -> bool:
    if log_path is None:
        return False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _count_proxy_events(log_path, event) >= count:
            return True
        time.sleep(0.1)
    return False


def _count_proxy_events(log_path: Path | None, event: str) -> int:
    if log_path is None or not log_path.exists():
        return 0
    count = 0
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if payload.get("event") == event:
                count += 1
    return count


def _proxy_payload_hashes(log_path: Path | None, event: str) -> set[str]:
    if log_path is None or not log_path.exists():
        return set()
    hashes: set[str] = set()
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("event") == event and isinstance(item.get("payload_sha256"), str):
                hashes.add(item["payload_sha256"])
    return hashes


def _proxy_forward_delays(log_path: Path | None) -> list[float]:
    if log_path is None or not log_path.exists():
        return []
    received: dict[str, deque[float]] = defaultdict(deque)
    delays: list[float] = []
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                item = json.loads(line)
                payload_hash = item.get("payload_sha256")
                timestamp = datetime.fromisoformat(str(item["ts"]).replace("Z", "+00:00")).timestamp()
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(payload_hash, str):
                continue
            if item.get("event") == "packet_received":
                received[payload_hash].append(timestamp)
            elif item.get("event") == "packet_forwarded" and received[payload_hash]:
                delays.append(max(0.0, timestamp - received[payload_hash].popleft()))
    return delays


def _has_actual_reorder(log_path: Path | None) -> bool:
    if log_path is None or not log_path.exists():
        return False
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("event") == "packets_reordered" and item.get("order_changed") is True:
                return True
    return False


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
    if scenario.id == "RF-LINK-008":
        scenario_extra += max(20.0, commands * (min(max(command_wait, 0.25), 0.75) + 3.0))
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
        result.raw.setdefault("health_reconnect", {"skipped": True, "reason": "session-managed link"})
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
    matching_payload_hashes = packet_summary.get("matching_payload_hashes", [])
    passed = False
    notes: list[str] = []

    if scenario.id == "RF-LINK-001":
        passed = (
            successful_system_responses > 0
            and packets_to_proxy > 0
            and target_entry_packets > 0
            and bool(matching_payload_hashes)
        )
    elif scenario.id == "RF-LINK-002":
        passed = packets_to_proxy >= 1 and packets_to_target < packets_to_proxy and successful_command_count < total_commands
    elif scenario.id == "RF-LINK-003":
        expected_delay = float(scenario.attack.get("delay_ms", 1000)) / 1000.0
        passed = (
            successful_system_responses > 0
            and packets_to_proxy > 0
            and max_delay is not None
            and float(max_delay) >= expected_delay * 0.8
        )
    elif scenario.id == "RF-LINK-004":
        passed = packets_to_proxy >= 1 and successful_system_responses > total_commands
    elif scenario.id == "RF-LINK-005":
        passed = packets_to_proxy >= 1 and successful_system_responses == 0 and error_event_count > 0
    elif scenario.id == "RF-LINK-008":
        window_size = int(scenario.attack.get("window_size", 4))
        passed = (
            int(packet_summary.get("proxy_received_packets", 0)) >= window_size
            and int(packet_summary.get("proxy_forwarded_packets", 0)) >= window_size
            and bool(packet_summary.get("actual_reorder_observed"))
            and successful_system_responses >= window_size
        )
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


def _write_downlink_summary(
    path: Path,
    scenario: Scenario,
    environment: LinkEnvironment,
    score: LiveScore,
    packet_summary: dict[str, object],
) -> None:
    session = score.evidence.get("downlink_session", {})
    if environment.link == "radio":
        session_details = f"""- RADIO enable destination: `{session.get('radio_service')}:{session.get('radio_service_port')}`
- RADIO interface/port: `{session.get('radio_interface')}:{session.get('radio_cosmos_port')}`
- RADIO session enabled: `{session.get('radio_downlink_enabled')}`
- RADIO session ready: `{session.get('radio_downlink_ready')}`
- RADIO session disabled: `{session.get('radio_downlink_disabled')}`"""
        stimulus = "DEBUG CFS SC_SEND_HK -> RADIO CFS_RADIO SC_HKTLM"
    else:
        session_details = f"""- DEBUG default route unchanged: `{session.get('debug_downlink_default')}`
- DEBUG source app: `{session.get('debug_source_app')}`
- DEBUG interface/port: `{session.get('debug_interface')}:{session.get('debug_cosmos_port')}`
- DEBUG intercept method: `{session.get('debug_intercept_method')}`
- DEBUG session ready: `{session.get('debug_downlink_ready')}`"""
        stimulus = "DEBUG CFS SC_SEND_HK -> DEBUG CFS SC_HKTLM"
    text = f"""# RF-link Downlink Case Summary

## Result

- Benchmark: `{scenario.id}` {scenario.name}
- Direction: `downlink`
- Telemetry source: `{environment.downlink_source_container}` ({environment.downlink_source_ip})
- COSMOS receiver: `{environment.downlink_destination}`
{session_details}
- Link session owner: `{session.get('owner')}`
- Stimulus: `{stimulus}`
- Passed: `{score.passed}`

## Evidence

- Telemetry stimulus responses: `{score.evidence['successful_telemetry_responses']}/{score.evidence['telemetry_stimulus_requests']}`
- Interceptor-rule packets: `{packet_summary.get('packets_redirected_by_dnat', 0)}`
- Proxy entry packets: `{packet_summary.get('proxy_entry_packets', 0)}`
- Proxy forwarded packets: `{packet_summary.get('proxy_forwarded_packets', 0)}`
- COSMOS receiver packets: `{packet_summary.get('receiver_entry_packets', 0)}`
- Maximum forwarding delay: `{packet_summary.get('max_forward_delay_seconds')}`

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
        f"- Direction cases passed: `{passed}/{len(scores)}`",
        "",
        "| Scenario | Uplink | Downlink | Key Evidence |",
        "| --- | --- | --- | --- |",
    ]
    scenario_names = {scenario.id: scenario.name for scenario in scenarios}
    by_scenario = {scenario.id: {} for scenario in scenarios}
    for score in scores:
        by_scenario.setdefault(score.scenario_id, {})[score.direction] = score
    for scenario in scenarios:
        scenario_scores = by_scenario.get(scenario.id, {})
        uplink = scenario_scores.get("uplink")
        downlink = scenario_scores.get("downlink")
        uplink_result = "-" if uplink is None else ("PASS" if uplink.passed else "FAIL")
        downlink_result = "-" if downlink is None else ("PASS" if downlink.passed else "FAIL")
        evidence_parts: list[str] = []
        if uplink:
            uplink_packets = dict(uplink.evidence.get("packet_summary", {}))
            if uplink.threat_model == "cryptographic-boundary":
                evidence_parts.append(
                    f"UL protected TCP {uplink_packets.get('source_payload_segments', 0)}->{uplink_packets.get('destination_payload_segments', 0)}, "
                    f"plaintext CCSDS {uplink_packets.get('complete_ccsds_segments', 0)}"
                )
            else:
                evidence_parts.append(
                    f"UL proxy {uplink_packets.get('proxy_entry_packets', uplink_packets.get('packets_to_proxy', 0))}, "
                    f"target {uplink_packets.get('target_entry_packets', uplink_packets.get('packets_to_target', 0))}"
                )
        if downlink:
            downlink_packets = dict(downlink.evidence.get("packet_summary", {}))
            if downlink.threat_model == "cryptographic-boundary":
                evidence_parts.append(
                    f"DL protected TCP {downlink_packets.get('source_payload_segments', 0)}->{downlink_packets.get('destination_payload_segments', 0)}, "
                    f"plaintext CCSDS {downlink_packets.get('complete_ccsds_segments', 0)}"
                )
            else:
                evidence_parts.append(
                    f"DL proxy {downlink_packets.get('proxy_entry_packets', 0)}, "
                    f"receiver {downlink_packets.get('receiver_entry_packets', 0)}"
                )
        lines.append(
            f"| `{scenario.id}` {scenario_names[scenario.id]} | {uplink_result} | {downlink_result} | "
            f"{' ; '.join(evidence_parts) or '-'} |"
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
