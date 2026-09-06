"""Lifecycle controller for the external cryptographic-boundary TCP MITM."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import subprocess
import time
import os
import re

from benchmark_engine.nos3.environment import discover_cryptographic_boundary_environment_host_only
from benchmark_engine.rf_link.threat_models import load_threat_model


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_IMAGE = "ivvitc/nos3-64:20251107"
NAME = "cfs-benchmark-cryptoboundary-mitm"
COMMENT = "cfs-benchmark-rf007-rf008-mitm"


def _host(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", "run", "--rm", "--privileged", "--net=host", "--pid=host", DEFAULT_IMAGE,
                           "nsenter", "--mount=/proc/1/ns/mnt", "--net=/proc/1/ns/net", "--root=/proc/1/root", *command],
                          check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _iptables(path, redirect_port: int, operation: str) -> None:
    # PREROUTING NAT is consulted only for a new TCP flow. Existing mission
    # sessions remain untouched until the user performs the one requested launch.
    try:
        interface = getattr(path, "host_veth", None) or _host_veth(path)
    except RuntimeError:
        # Docker's FDB learns only after traffic; exact tuple matching at the
        # host PREROUTING hook is still external and avoids namespace access.
        interface = None
    rule = (["-i", interface] if interface else []) + ["-s", path.source_ip, "-d", path.destination_ip,
            "-p", "tcp", "--dport", str(path.destination_port), "-m", "comment", "--comment", COMMENT,
            "-j", "REDIRECT", "--to-ports", str(redirect_port)]
    _host(["/usr/sbin/iptables", "-t", "nat", operation, "PREROUTING", *rule], check=operation == "-I")


def _host_veth(path) -> str:
    """Map an endpoint MAC to its host bridge port without entering its netns."""
    result = subprocess.run(["bridge", "fdb", "show", "br", path.bridge_interface], check=True, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    match = re.search(rf"^{re.escape(path.source_mac)}\\s+dev\\s+(\\S+)", result.stdout, re.MULTILINE | re.IGNORECASE)
    if not match:
        raise RuntimeError(f"host veth for {path.source_mac} on {path.bridge_interface} is not present")
    return match.group(1)


def control(port: int, request: dict[str, object]) -> dict[str, object]:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.sendall(json.dumps(request).encode("utf-8"))
        return json.loads(conn.recv(65535).decode("utf-8"))


def prepare(args: argparse.Namespace) -> None:
    model = load_threat_model("cryptographic-boundary", ROOT)
    boundary = discover_cryptographic_boundary_environment_host_only(model)
    uplink, downlink = boundary.path_for("uplink"), boundary.path_for("downlink")
    state = args.state.resolve(); state.parent.mkdir(parents=True, exist_ok=True)
    log = args.log.resolve(); log.parent.mkdir(parents=True, exist_ok=True)
    # Keep the relay out of Docker.  NOS3's make stop removes benchmark-named
    # containers, while a VM-host process survives the user-authorized
    # stop/launch boundary and is still outside both endpoint namespaces.
    old_pid = state.with_suffix(".pid")
    if old_pid.exists():
        try: os.kill(int(old_pid.read_text().strip()), 15)
        except (ProcessLookupError, ValueError): pass
    host_log = state.with_suffix(".proxy.stdout.log")
    with host_log.open("ab") as output:
        process = subprocess.Popen([
            "python3", "-m", "benchmark_engine.rf_link.tcp_mitm", "--uplink-target", uplink.destination,
            "--downlink-target", downlink.destination, "--uplink-port", str(args.uplink_port),
            "--downlink-port", str(args.downlink_port), "--control-port", str(args.control_port), "--log", str(log),
        ], cwd=ROOT, stdin=subprocess.DEVNULL, stdout=output, stderr=output, start_new_session=True)
    old_pid.write_text(str(process.pid) + "\n", encoding="utf-8")
    try:
        time.sleep(0.5); control(args.control_port, {"action": "snapshot"})
        _iptables(uplink, args.uplink_port, "-I"); _iptables(downlink, args.downlink_port, "-I")
    except Exception:
        _iptables(uplink, args.uplink_port, "-D"); _iptables(downlink, args.downlink_port, "-D")
        try: os.kill(process.pid, 15)
        except ProcessLookupError: pass
        raise
    uplink_state, downlink_state = uplink.__dict__.copy(), downlink.__dict__.copy()
    for item, path in ((uplink_state, uplink), (downlink_state, downlink)):
        try: item["host_veth"] = _host_veth(path)
        except RuntimeError: item["host_veth"] = None
    state.write_text(json.dumps({"paths": {"uplink": uplink_state, "downlink": downlink_state},
                                 "bridge_interface": uplink.bridge_interface, "control_port": args.control_port,
                                 "ports": {"uplink": args.uplink_port, "downlink": args.downlink_port},
                                 "session_owner": "suite-owned-external-tcp-mitm", "endpoint_namespace_access": False,
                                 "process_restart": False, "armed_before_user_launch": True}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"prepared": True, "state": str(state), "snapshot": control(args.control_port, {"action": "snapshot"})}))


def cleanup(args: argparse.Namespace) -> None:
    state = json.loads(args.state.read_text(encoding="utf-8"))
    warnings: list[str] = []
    for direction in ("uplink", "downlink"):
        path = type("Path", (), state["paths"][direction])()
        try: _iptables(path, int(state["ports"][direction]), "-D")
        except Exception as error: warnings.append(f"{direction} rule: {error}")
    try: control(int(state["control_port"]), {"action": "stop"})
    except Exception as error: warnings.append(f"proxy stop: {error}")
    pid_path = args.state.with_suffix(".pid")
    if pid_path.exists():
        try: os.kill(int(pid_path.read_text().strip()), 15)
        except (ProcessLookupError, ValueError) as error: warnings.append(f"host proxy: {error}")
    print(json.dumps({"cleanup_warning": warnings, "rules_and_proxy_cleanup_attempted": True}))


def main() -> None:
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "cleanup"):
        p = sub.add_parser(name); p.add_argument("--state", type=Path, required=True); p.add_argument("--image", default=DEFAULT_IMAGE)
        p.add_argument("--uplink-port", type=int, default=18010); p.add_argument("--downlink-port", type=int, default=18011); p.add_argument("--control-port", type=int, default=18990)
        p.add_argument("--log", type=Path, default=ROOT / "artifacts" / "tcp_mitm.jsonl")
    args = parser.parse_args()
    if args.command == "prepare": prepare(args)
    else: cleanup(args)


if __name__ == "__main__": main()
