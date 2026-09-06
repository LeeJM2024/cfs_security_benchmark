from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
from typing import Any

from benchmark_engine.rf_link.threat_models import ThreatModel


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
    downlink_source_name: str
    downlink_source_container: str
    downlink_source_pid: str
    downlink_source_ip: str
    downlink_destination_port: int
    downlink_destination: str
    downlink_destination_interface: str
    downlink_proxy_host: str
    telemetry_target: str
    telemetry_request_command: str
    telemetry_packet: str
    telemetry_freshness_item: str
    radio_downlink_service: str
    radio_downlink_service_port: int
    radio_downlink_interface: str
    radio_downlink_cosmos_port: int


@dataclass(frozen=True)
class CryptographicBoundaryPath:
    direction: str
    transport: str
    source_container: str
    source_pid: str
    source_ip: str
    source_interface: str
    destination_container: str
    destination_pid: str
    destination_ip: str
    source_mac: str
    destination_mac: str
    network_name: str
    bridge_interface: str
    destination_interface: str
    destination_port: int

    @property
    def destination(self) -> str:
        return f"{self.destination_ip}:{self.destination_port}"


@dataclass(frozen=True)
class CryptographicBoundaryEnvironment:
    link: str
    paths: dict[str, CryptographicBoundaryPath]

    def path_for(self, direction: str) -> CryptographicBoundaryPath:
        try:
            return self.paths[direction]
        except KeyError as error:
            raise ValueError(f"cryptographic boundary has no {direction} path") from error


def discover_link_environment(link: str, cosmos_container: str) -> LinkEnvironment:
    link = link.lower()
    if link == "debug":
        target_name = "nos-fsw"
        target_port = 5012
        cosmos_target = "CFS"
        cosmos_interface = "DEBUG"
        downlink_destination_port = 5013
        downlink_source_name = "TO_LAB"
        telemetry_target = "GENERIC_EPS"
    elif link == "radio":
        target_name = "cryptolib"
        target_port = 6010
        cosmos_target = "CFS_RADIO"
        cosmos_interface = "RADIO"
        downlink_destination_port = 6011
        downlink_source_name = target_name
        telemetry_target = "GENERIC_EPS_RADIO"
    else:
        raise ValueError("link must be 'debug' or 'radio'")

    target_ip = _docker_exec(cosmos_container, "getent", "hosts", target_name).split()[0]
    route = _docker_exec(cosmos_container, "ip", "route", "get", target_ip)
    cosmos_ip = _extract_route_source(route)
    container_info = _docker_json("inspect", cosmos_container)[0]
    network_name, proxy_host = _network_for_ip(container_info, cosmos_ip)
    cosmos_pid = str(container_info["State"]["Pid"])
    downlink_destination_interface = _interface_for_ip(cosmos_container, cosmos_ip)
    bridge_interface = _bridge_interface(network_name)
    downlink_source_container, downlink_source_info = _container_for_ip(target_ip)
    downlink_source_pid = str(downlink_source_info["State"]["Pid"])
    _, downlink_proxy_host = _network_for_ip(downlink_source_info, target_ip)

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
        downlink_source_name=downlink_source_name,
        downlink_source_container=downlink_source_container,
        downlink_source_pid=downlink_source_pid,
        downlink_source_ip=target_ip,
        downlink_destination_port=downlink_destination_port,
        downlink_destination=f"{cosmos_ip}:{downlink_destination_port}",
        downlink_destination_interface=downlink_destination_interface,
        downlink_proxy_host=downlink_proxy_host,
        telemetry_target=telemetry_target,
        telemetry_request_command="GENERIC_EPS_REQ_HK",
        telemetry_packet="GENERIC_EPS_HK_TLM",
        telemetry_freshness_item="CMD_COUNT",
        radio_downlink_service="radio-sim",
        radio_downlink_service_port=5011,
        radio_downlink_interface="RADIO",
        radio_downlink_cosmos_port=6011,
    )


def discover_cryptographic_boundary_environment(model: ThreatModel) -> CryptographicBoundaryEnvironment:
    """Resolve the live CryptoLib-radio-sim protected paths without Docker IP literals."""
    if "radio" not in model.supported_links:
        raise ValueError(f"threat model {model.id} does not define a RADIO protected path")

    paths: dict[str, CryptographicBoundaryPath] = {}
    for direction in ("uplink", "downlink"):
        profile = model.path_for(direction)
        if profile.transport != "tcp":
            raise ValueError(f"{model.id} {direction} path must use tcp, got {profile.transport}")
        source_container, source_info, source_ip = _container_for_alias(profile.source_alias)
        destination_container, destination_info, destination_ip = _container_for_alias(profile.destination_alias)
        source_network, source_mac = _network_name_and_mac(source_info, source_ip)
        destination_network, destination_mac = _network_name_and_mac(destination_info, destination_ip)
        if source_network != destination_network:
            raise RuntimeError(
                f"cryptographic boundary endpoints are not on the same Docker network: "
                f"{source_network} != {destination_network}"
            )
        paths[direction] = CryptographicBoundaryPath(
            direction=direction,
            transport=profile.transport,
            source_container=source_container,
            source_pid=str(source_info["State"]["Pid"]),
            source_ip=source_ip,
            source_interface=_interface_for_route(source_container, destination_ip),
            destination_container=destination_container,
            destination_pid=str(destination_info["State"]["Pid"]),
            destination_ip=destination_ip,
            source_mac=source_mac,
            destination_mac=destination_mac,
            network_name=source_network,
            bridge_interface=_bridge_interface(source_network),
            destination_interface=_interface_for_ip(destination_container, destination_ip),
            destination_port=profile.destination_port,
        )
    return CryptographicBoundaryEnvironment(link="radio", paths=paths)


def discover_cryptographic_boundary_environment_host_only(model: ThreatModel) -> CryptographicBoundaryEnvironment:
    """Resolve protected paths from Docker metadata without endpoint exec/nsenter.

    This variant is for the external MITM controller.  Endpoint interface names
    are intentionally not inspected because the controller operates on the
    host bridge, not on a container veth.
    """
    if "radio" not in model.supported_links:
        raise ValueError(f"threat model {model.id} does not define a RADIO protected path")
    container_ids = [line for line in subprocess.run(
        ["docker", "ps", "-q"], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout.splitlines() if line.strip()]
    infos: list[dict[str, Any]] = []
    for container_id in container_ids:
        # A short-lived Docker helper may disappear between ps and inspect.
        # Ignore only that race; aliases are resolved from the remaining live
        # endpoints and no endpoint namespace is entered.
        try:
            infos.extend(_docker_json("inspect", container_id))
        except subprocess.CalledProcessError:
            continue
    def resolve(alias: str) -> tuple[str, dict[str, Any], str]:
        for info in infos:
            for data in info.get("NetworkSettings", {}).get("Networks", {}).values():
                if alias in (set(data.get("Aliases") or []) | set(data.get("DNSNames") or [])):
                    return str(info["Name"]).lstrip("/"), info, str(data["IPAddress"])
        raise RuntimeError(f"could not find a running Docker container with network alias {alias}")
    paths: dict[str, CryptographicBoundaryPath] = {}
    for direction in ("uplink", "downlink"):
        profile = model.path_for(direction)
        source_container, source_info, source_ip = resolve(profile.source_alias)
        destination_container, destination_info, destination_ip = resolve(profile.destination_alias)
        network_name, source_mac = _network_name_and_mac(source_info, source_ip)
        destination_network, destination_mac = _network_name_and_mac(destination_info, destination_ip)
        if network_name != destination_network:
            raise RuntimeError("cryptographic boundary endpoints are not on the same Docker network")
        paths[direction] = CryptographicBoundaryPath(
            direction=direction, transport=profile.transport, source_container=source_container,
            source_pid=str(source_info["State"]["Pid"]), source_ip=source_ip, source_interface="not_inspected",
            destination_container=destination_container, destination_pid=str(destination_info["State"]["Pid"]),
            destination_ip=destination_ip, source_mac=source_mac, destination_mac=destination_mac,
            network_name=network_name, bridge_interface=_bridge_interface(network_name),
            destination_interface="not_inspected", destination_port=profile.destination_port,
        )
    return CryptographicBoundaryEnvironment(link="radio", paths=paths)


def write_environment(path: Path, environment: LinkEnvironment) -> None:
    path.write_text(json.dumps(environment.__dict__, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _interface_for_ip(container: str, address: str) -> str:
    try:
        output = _docker_exec(container, "ip", "-o", "-4", "addr", "show")
    except subprocess.CalledProcessError:
        return _single_non_loopback_interface(container)
    for line in output.splitlines():
        match = re.match(r"^\d+:\s+(\S+)\s+inet\s+([^/]+)/", line)
        if match and match.group(2) == address:
            return match.group(1)
    return _single_non_loopback_interface(container)


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


def _network_name_and_mac(container_info: dict, ip_address: str) -> tuple[str, str]:
    for name, data in container_info["NetworkSettings"]["Networks"].items():
        if data.get("IPAddress") == ip_address:
            mac = data.get("MacAddress")
            if not mac:
                raise RuntimeError(f"network {name} has no MAC address for {ip_address}")
            return name, str(mac)
    raise RuntimeError(f"could not find a Docker network for {ip_address}")


def _container_for_ip(ip_address: str) -> tuple[str, dict]:
    result = subprocess.run(
        ["docker", "ps", "-q"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    container_ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not container_ids:
        raise RuntimeError(f"could not find a running Docker container for {ip_address}")

    for info in _docker_json("inspect", *container_ids):
        for network in info.get("NetworkSettings", {}).get("Networks", {}).values():
            if network.get("IPAddress") == ip_address:
                return str(info["Name"]).lstrip("/"), info
    raise RuntimeError(f"could not find a running Docker container for {ip_address}")


def _container_for_alias(alias: str) -> tuple[str, dict[str, Any], str]:
    result = subprocess.run(
        ["docker", "ps", "-q"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    container_ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    for info in _docker_json("inspect", *container_ids):
        for network in info.get("NetworkSettings", {}).get("Networks", {}).values():
            aliases = set(network.get("Aliases") or []) | set(network.get("DNSNames") or [])
            if alias in aliases:
                return str(info["Name"]).lstrip("/"), info, str(network["IPAddress"])
    raise RuntimeError(f"could not find a running Docker container with network alias {alias}")


def _interface_for_route(container: str, destination_ip: str) -> str:
    try:
        route = _docker_exec(container, "ip", "route", "get", destination_ip)
    except subprocess.CalledProcessError:
        return _single_non_loopback_interface(container)
    parts = route.split()
    for index, part in enumerate(parts):
        if part == "dev" and index + 1 < len(parts):
            return parts[index + 1]
    raise RuntimeError(f"could not identify route interface from {container} to {destination_ip}")


def _single_non_loopback_interface(container: str) -> str:
    output = _docker_exec(container, "cat", "/proc/net/dev")
    interfaces = [
        line.split(":", 1)[0].strip()
        for line in output.splitlines()[2:]
        if ":" in line and line.split(":", 1)[0].strip() != "lo"
    ]
    if len(interfaces) == 1:
        return interfaces[0]
    if "eth0" in interfaces:
        return "eth0"
    raise RuntimeError(f"could not identify a non-loopback interface in {container}: {interfaces}")


def _bridge_interface(network_name: str) -> str:
    network = _docker_json("network", "inspect", network_name)[0]
    bridge = network.get("Options", {}).get("com.docker.network.bridge.name")
    if not bridge:
        bridge = "br-" + network["Id"][:12]
    if Path("/sys/class/net", bridge).exists():
        return bridge
    return "any"
