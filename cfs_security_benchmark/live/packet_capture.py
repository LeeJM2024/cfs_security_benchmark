from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid


@dataclass(frozen=True)
class UdpPacketObservation:
    timestamp: float
    source: str
    source_port: int
    destination: str
    destination_port: int
    length: int


class TcpdumpCapture:
    def __init__(
        self,
        *,
        interface: str,
        pcap_path: Path,
        observation_path: Path,
        ports: list[int],
        image: str | None = None,
        mount_root: Path | None = None,
        duration: float | None = None,
        network_container: str | None = None,
    ):
        self.interface = interface
        self.pcap_path = pcap_path
        self.observation_path = observation_path
        self.ports = ports
        self.image = image
        self.mount_root = mount_root
        self.duration = duration
        self.network_container = network_container
        self.container_name = f"cfs-benchmark-capture-{uuid.uuid4().hex[:12]}"
        self.process: subprocess.Popen | None = None

    def start(self) -> None:
        self.pcap_path.parent.mkdir(parents=True, exist_ok=True)
        if self.image and self.mount_root:
            capture_path = "/bench/" + str(self.pcap_path.relative_to(self.mount_root))
            observation_path = "/bench/" + str(self.observation_path.relative_to(self.mount_root))
            command = [
                "docker",
                "run",
                "--rm",
                "--name",
                self.container_name,
                "--privileged",
                "-v",
                f"{self.mount_root}:/bench",
                "-w",
                "/bench",
                self.image,
                "python3",
                "-m",
                "cfs_security_benchmark.live.raw_capture",
                "--interface",
                self.interface,
                "--pcap",
                capture_path,
                "--jsonl",
                observation_path,
                "--duration",
                str(self.duration or 30),
                "--ports",
                *[str(port) for port in self.ports],
            ]
            if self.network_container:
                command.insert(4, f"--network=container:{self.network_container}")
            else:
                command.insert(4, "--net=host")
        else:
            port_filter = " or ".join(f"port {port}" for port in self.ports)
            command = [
                *_privilege_prefix(),
                "tcpdump",
                "-i",
                self.interface,
                "-nn",
                "-tt",
                "-w",
                str(self.pcap_path),
                "udp",
                "and",
                "(",
                *port_filter.split(),
                ")",
            ]
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(1.0)

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            if self.image and self.mount_root:
                subprocess.run(["docker", "stop", "-t", "1", self.container_name], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate(timeout=5)
        self.process = None

    def __enter__(self) -> "TcpdumpCapture":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


def read_udp_observations(pcap_path: Path, ports: list[int], observation_path: Path | None = None) -> list[UdpPacketObservation]:
    if observation_path and observation_path.exists():
        observations: list[UdpPacketObservation] = []
        for line in observation_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = __import__("json").loads(line)
            observations.append(
                UdpPacketObservation(
                    timestamp=float(item["timestamp"]),
                    source=str(item["source"]),
                    source_port=int(item["source_port"]),
                    destination=str(item["destination"]),
                    destination_port=int(item["destination_port"]),
                    length=int(item["length"]),
                )
            )
        return observations

    if not pcap_path.exists():
        return []
    port_filter = " or ".join(f"port {port}" for port in ports)
    result = subprocess.run(
        ["tcpdump", "-tt", "-nn", "-r", str(pcap_path), "udp", "and", "(", *port_filter.split(), ")"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    observations: list[UdpPacketObservation] = []
    for line in result.stdout.splitlines():
        parsed = _parse_tcpdump_line(line)
        if parsed:
            observations.append(parsed)
    return observations


def summarize_link_packets(
    observations: list[UdpPacketObservation],
    *,
    listen_port: int,
    target_ip: str,
    target_port: int,
) -> dict[str, object]:
    to_proxy = [packet for packet in observations if packet.destination_port == listen_port]
    to_target = [
        packet
        for packet in observations
        if packet.destination == target_ip and packet.destination_port == target_port
    ]
    delays = []
    for left, right in zip(to_proxy, to_target):
        delays.append(max(0.0, right.timestamp - left.timestamp))

    return {
        "total_udp_packets": len(observations),
        "packets_to_proxy": len(to_proxy),
        "packets_to_target": len(to_target),
        "forward_delays_seconds": delays,
        "max_forward_delay_seconds": max(delays) if delays else None,
    }


def _privilege_prefix() -> list[str]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []
    return ["sudo"]


_TCPDUMP_RE = re.compile(
    r"^(?P<ts>\d+(?:\.\d+)?) IP "
    r"(?P<src>.+)\.(?P<src_port>\d+) > "
    r"(?P<dst>.+)\.(?P<dst_port>\d+): UDP, length (?P<length>\d+)"
)


def _parse_tcpdump_line(line: str) -> UdpPacketObservation | None:
    match = _TCPDUMP_RE.search(line.strip())
    if not match:
        return None
    return UdpPacketObservation(
        timestamp=float(match.group("ts")),
        source=match.group("src"),
        source_port=int(match.group("src_port")),
        destination=match.group("dst"),
        destination_port=int(match.group("dst_port")),
        length=int(match.group("length")),
    )
