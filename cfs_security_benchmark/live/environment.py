from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess


@dataclass(frozen=True)
class LinkEnvironment:
    link: str
    cosmos_container: str
    cosmos_pid: str
    cosmos_ip: str
    target_name: str
    target_ip: str
    target_port: int
    target: str
    cosmos_target: str
    cosmos_interface: str
    housekeeping_packet: str
    command_counter_item: str
    noop_command: str
    housekeeping_command: str
    proxy_host: str
    bridge_interface: str


def discover_link_environment(link: str, cosmos_container: str) -> LinkEnvironment:
    link = link.lower()
    if link == "debug":
        target_name = "nos-fsw"
        target_port = 5012
        cosmos_target = "CFS"
        cosmos_interface = "DEBUG"
    elif link == "radio":
        target_name = "cryptolib"
        target_port = 6010
        cosmos_target = "CFS_RADIO"
        cosmos_interface = "RADIO"
    else:
        raise ValueError("link must be 'debug' or 'radio'")

    target_ip = _docker_exec(cosmos_container, "getent", "hosts", target_name).split()[0]
    route = _docker_exec(cosmos_container, "ip", "route", "get", target_ip)
    cosmos_ip = _extract_route_source(route)
    container_info = _docker_json("inspect", cosmos_container)[0]
    network_name, proxy_host = _network_for_ip(container_info, cosmos_ip)
    cosmos_pid = str(container_info["State"]["Pid"])
    bridge_interface = _bridge_interface(network_name)

    return LinkEnvironment(
        link=link,
        cosmos_container=cosmos_container,
        cosmos_pid=cosmos_pid,
        cosmos_ip=cosmos_ip,
        target_name=target_name,
        target_ip=target_ip,
        target_port=target_port,
        target=f"{target_ip}:{target_port}",
        cosmos_target=cosmos_target,
        cosmos_interface=cosmos_interface,
        housekeeping_packet="CFE_ES_HKPACKET",
        command_counter_item="CMDCOUNTER",
        noop_command="CFE_ES_NOOP",
        housekeeping_command="",
        proxy_host=proxy_host,
        bridge_interface=bridge_interface,
    )


def write_environment(path: Path, environment: LinkEnvironment) -> None:
    path.write_text(json.dumps(environment.__dict__, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _docker_exec(container: str, *args: str) -> str:
    result = subprocess.run(
        ["docker", "exec", container, *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def _docker_json(*args: str):
    result = subprocess.run(
        ["docker", *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return json.loads(result.stdout)


def _extract_route_source(route: str) -> str:
    parts = route.split()
    for index, part in enumerate(parts):
        if part == "src" and index + 1 < len(parts):
            return parts[index + 1]
    raise RuntimeError(f"could not extract COSMOS source IP from route: {route}")


def _network_for_ip(container_info: dict, ip_address: str) -> tuple[str, str]:
    networks = container_info["NetworkSettings"]["Networks"]
    for name, data in networks.items():
        if data.get("IPAddress") == ip_address:
            gateway = data.get("Gateway")
            if not gateway:
                raise RuntimeError(f"network {name} has no gateway")
            return name, gateway
    raise RuntimeError(f"could not find Docker network for COSMOS IP {ip_address}")


def _bridge_interface(network_name: str) -> str:
    network = _docker_json("network", "inspect", network_name)[0]
    bridge = network.get("Options", {}).get("com.docker.network.bridge.name")
    if not bridge:
        bridge = "br-" + network["Id"][:12]
    if Path("/sys/class/net", bridge).exists():
        return bridge
    return "any"
