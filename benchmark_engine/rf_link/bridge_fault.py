from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess

from benchmark_engine.nos3.environment import CryptographicBoundaryPath


DEFAULT_IMAGE = "ivvitc/nos3-64:20251107"


@dataclass
class ProtectedBridgeDrop:
    """Lab RF-medium fault on the host side of a source veth, outside endpoints."""

    path: CryptographicBoundaryPath
    preference: int
    image: str = DEFAULT_IMAGE
    bridge: str = ""
    installed: bool = False

    def start(self) -> None:
        self.bridge = _host_peer_interface(self.path.source_container, self.path.source_interface, self.image)
        _ensure_clsact(self._tc, self.bridge)
        self._tc(
            "filter", "add", "dev", self.bridge, "ingress", "pref", str(self.preference), "protocol", "ip",
            "flower", "src_ip", self.path.source_ip, "dst_ip", self.path.destination_ip,
            "ip_proto", "tcp", "dst_port", str(self.path.destination_port), "action", "drop",
        )
        self.installed = True

    def stop(self) -> dict[str, object]:
        evidence = self.snapshot()
        if self.installed:
            self._tc("filter", "del", "dev", self.bridge, "ingress", "pref", str(self.preference), "protocol", "ip", check=False)
            self.installed = False
        evidence["filter_removed"] = not self.installed
        return evidence

    def snapshot(self) -> dict[str, object]:
        result = self._tc("-s", "filter", "show", "dev", self.bridge, "ingress", check=False)
        text = result.stdout
        selected = _selected_filter_block(text, self.preference)
        packets = 0
        bytes_seen = 0
        match = re.search(r"Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt", selected)
        if match:
            bytes_seen, packets = int(match.group(1)), int(match.group(2))
        return {
            "host_veth": self.bridge,
            "preference": self.preference,
            "found": bool(selected),
            "packets": packets,
            "bytes": bytes_seen,
            "filter": selected,
            "placement": "host_side_of_source_veth_outside_endpoints",
            "endpoint_namespace_access": False,
        }

    def _tc(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "docker", "run", "--rm", "--privileged", "--net=host", "--pid=host", self.image,
                "nsenter", "--mount=/proc/1/ns/mnt", "--net=/proc/1/ns/net", "--root=/proc/1/root",
                "/usr/sbin/tc", *arguments,
            ],
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


@dataclass
class ProtectedBridgeCiphertextMutation:
    """Mutate protected payload bytes on the host side of a source veth.

    ``pedit`` is paired with ``csum tcp`` so the changed frame reaches the
    receiving socket.  This avoids measuring a TCP checksum rejection instead
    of the protected-frame integrity boundary.
    """

    path: CryptographicBoundaryPath
    preference: int
    payload_offset_from_ip: int = 76
    image: str = DEFAULT_IMAGE
    bridge: str = ""
    installed: bool = False

    def start(self) -> None:
        self.bridge = _host_peer_interface(self.path.source_container, self.path.source_interface, self.image)
        _ensure_clsact(self._tc, self.bridge)
        self._tc(
            "filter", "add", "dev", self.bridge, "ingress", "pref", str(self.preference), "protocol", "ip",
            "flower", "src_ip", self.path.source_ip, "dst_ip", self.path.destination_ip,
            "ip_proto", "tcp", "dst_port", str(self.path.destination_port), "tcp_flags", "0x18/0x18",
            "action", "pedit", "munge", "offset", str(self.payload_offset_from_ip), "u32", "invert", "pipe",
            "action", "csum", "tcp",
        )
        self.installed = True

    def stop(self) -> dict[str, object]:
        evidence = self.snapshot()
        if self.installed:
            self._tc("filter", "del", "dev", self.bridge, "ingress", "pref", str(self.preference), "protocol", "ip", check=False)
            self.installed = False
        evidence["filter_removed"] = not self.installed
        return evidence

    def snapshot(self) -> dict[str, object]:
        result = self._tc("-s", "filter", "show", "dev", self.bridge, "ingress", check=False)
        selected = _selected_filter_block(result.stdout, self.preference)
        match = re.search(r"Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt", selected)
        bytes_seen, packets = (int(match.group(1)), int(match.group(2))) if match else (0, 0)
        return {
            "host_veth": self.bridge,
            "preference": self.preference,
            "found": bool(selected),
            "packets": packets,
            "bytes": bytes_seen,
            "filter": selected,
            "mutation": "invert_u32_then_recompute_tcp_checksum",
            "payload_offset_from_ip": self.payload_offset_from_ip,
            "placement": "host_side_of_source_veth_outside_endpoints",
            "endpoint_namespace_access": False,
        }

    def _tc(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "docker", "run", "--rm", "--privileged", "--net=host", "--pid=host", self.image,
                "nsenter", "--mount=/proc/1/ns/mnt", "--net=/proc/1/ns/net", "--root=/proc/1/root",
                "/usr/sbin/tc", *arguments,
            ],
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


@dataclass
class ProtectedMediumFlood:
    """Emit bounded non-session TCP payloads onto a destination host-veth.

    This is intentionally a transport-pressure smoke test.  The packets have
    valid IPv4/TCP checksums but a distinct source tuple, so they cannot alter
    the active protected connection or claim a CryptoLib application-level DoS.
    """

    path: CryptographicBoundaryPath
    project_root: Path
    rate_per_second: float
    payload_size: int
    duration_seconds: float
    image: str = DEFAULT_IMAGE
    interface: str = ""

    def run(self) -> dict[str, object]:
        self.interface = _host_peer_interface(self.path.destination_container, self.path.destination_interface, self.image)
        result = subprocess.run(
            [
                "docker", "run", "--rm", "--privileged", "--net=host",
                "-v", f"{self.project_root}:/bench", "-w", "/bench", self.image,
                "python3", "-m", "benchmark_engine.rf_link.flood_injector",
                "--interface", self.interface,
                "--destination-mac", self.path.destination_mac,
                "--destination-ip", self.path.destination_ip,
                "--destination-port", str(self.path.destination_port),
                "--rate", str(self.rate_per_second),
                "--payload-size", str(self.payload_size),
                "--duration", str(self.duration_seconds),
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if not lines:
            raise RuntimeError("flood injector produced no evidence")
        evidence = json.loads(lines[-1])
        return {
            **evidence,
            "host_veth": self.interface,
            "placement": "host_side_of_destination_veth_outside_endpoints",
            "endpoint_namespace_access": False,
            "active_protected_connection_modified": False,
        }


def _host_peer_interface(container: str, interface: str, image: str) -> str:
    iflink = subprocess.run(
        ["docker", "exec", container, "cat", f"/sys/class/net/{interface}/iflink"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    result = subprocess.run(
        [
            "docker", "run", "--rm", "--privileged", "--net=host", "--pid=host", image,
            "nsenter", "--mount=/proc/1/ns/mnt", "--net=/proc/1/ns/net", "--root=/proc/1/root",
            "/sbin/ip", "-o", "link", "show",
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    for line in result.stdout.splitlines():
        match = re.match(r"^(\d+):\s*([^:@]+)", line)
        if match and match.group(1) == iflink:
            return match.group(2)
    raise RuntimeError(f"could not find host peer interface for {container}:{interface} (iflink {iflink})")


def _ensure_clsact(tc, interface: str) -> None:
    result = tc("qdisc", "add", "dev", interface, "clsact", check=False)
    if result.returncode == 0 or "Exclusivity flag on" in result.stderr:
        return
    raise RuntimeError(result.stderr.strip() or f"could not create clsact qdisc on {interface}")


@dataclass
class ProtectedMediumDelay:
    """Delay one protected TCP flow at the destination host-veth egress."""

    path: CryptographicBoundaryPath
    preference: int
    delay_ms: int
    image: str = DEFAULT_IMAGE
    interface: str = ""
    installed: bool = False

    def start(self) -> None:
        self.interface = _host_peer_interface(self.path.destination_container, self.path.destination_interface, self.image)
        before = self._tc("qdisc", "show", "dev", self.interface)
        if "noqueue" not in before.stdout:
            raise RuntimeError(f"refusing to replace non-default qdisc on {self.interface}: {before.stdout.strip()}")
        self._tc("qdisc", "replace", "dev", self.interface, "root", "handle", "1:", "prio", "bands", "3")
        self._tc("qdisc", "add", "dev", self.interface, "parent", "1:1", "handle", "10:", "netem", "delay", f"{self.delay_ms}ms")
        self._tc(
            "filter", "add", "dev", self.interface, "parent", "1:", "pref", str(self.preference), "protocol", "ip",
            "flower", "src_ip", self.path.source_ip, "dst_ip", self.path.destination_ip,
            "ip_proto", "tcp", "dst_port", str(self.path.destination_port), "flowid", "1:1",
        )
        self.installed = True

    def stop(self) -> dict[str, object]:
        evidence = self.snapshot()
        if self.installed:
            self._tc("qdisc", "del", "dev", self.interface, "root", check=False)
            self.installed = False
        evidence["qdisc_removed"] = not self.installed
        return evidence

    def snapshot(self) -> dict[str, object]:
        qdisc = self._tc("qdisc", "show", "dev", self.interface, check=False)
        filters = self._tc("-s", "filter", "show", "dev", self.interface, "parent", "1:", check=False)
        return {
            "host_veth": self.interface,
            "preference": self.preference,
            "delay_ms": self.delay_ms,
            "qdisc": qdisc.stdout,
            "filter": _selected_filter_block(filters.stdout, self.preference),
            "placement": "host_side_of_destination_veth_outside_endpoints",
            "endpoint_namespace_access": False,
        }

    def _tc(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "docker", "run", "--rm", "--privileged", "--net=host", "--pid=host", self.image,
                "nsenter", "--mount=/proc/1/ns/mnt", "--net=/proc/1/ns/net", "--root=/proc/1/root",
                "/usr/sbin/tc", *arguments,
            ],
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


def _selected_filter_block(text: str, preference: int) -> str:
    chunks = re.split(r"(?=filter protocol )", text)
    needle = f"pref {preference} "
    return next((chunk.strip() for chunk in chunks if needle in chunk), "")
