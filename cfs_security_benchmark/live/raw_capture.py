from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import struct
import time


ETH_P_ALL = 0x0003
ETHERNET_LINKTYPE = 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture UDP packets as independent live benchmark evidence")
    parser.add_argument("--interface", required=True, help="Network interface to capture, such as br-xxxx")
    parser.add_argument("--pcap", type=Path, required=True, help="Output pcap path")
    parser.add_argument("--jsonl", type=Path, required=True, help="Output packet observation JSONL path")
    parser.add_argument("--ports", type=int, nargs="+", required=True, help="UDP ports to capture")
    parser.add_argument("--duration", type=float, required=True, help="Capture duration in seconds")
    args = parser.parse_args()

    args.pcap.parent.mkdir(parents=True, exist_ok=True)
    args.jsonl.parent.mkdir(parents=True, exist_ok=True)

    ports = set(args.ports)
    deadline = time.monotonic() + args.duration
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((args.interface, 0))
    sock.settimeout(0.2)

    with sock, args.pcap.open("wb") as pcap, args.jsonl.open("w", encoding="utf-8") as jsonl:
        _write_pcap_header(pcap)
        while time.monotonic() < deadline:
            try:
                frame = sock.recv(65535)
            except socket.timeout:
                continue

            observation = _parse_udp_frame(frame)
            if observation is None:
                continue
            if observation["source_port"] not in ports and observation["destination_port"] not in ports:
                continue

            timestamp = time.time()
            _write_pcap_packet(pcap, frame, timestamp)
            observation["ts"] = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
            observation["timestamp"] = timestamp
            jsonl.write(json.dumps(observation, sort_keys=True) + "\n")
            jsonl.flush()


def _write_pcap_header(handle) -> None:
    handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, ETHERNET_LINKTYPE))


def _write_pcap_packet(handle, frame: bytes, timestamp: float) -> None:
    seconds = int(timestamp)
    microseconds = int((timestamp - seconds) * 1_000_000)
    handle.write(struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)))
    handle.write(frame)
    handle.flush()


def _parse_udp_frame(frame: bytes) -> dict[str, object] | None:
    ip_offset = _find_ipv4_udp_offset(frame)
    if ip_offset is None:
        return None

    version_ihl = frame[ip_offset]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or ihl < 20:
        return None

    protocol = frame[ip_offset + 9]
    if protocol != 17:
        return None

    udp_offset = ip_offset + ihl
    if len(frame) < udp_offset + 8:
        return None

    source = socket.inet_ntoa(frame[ip_offset + 12 : ip_offset + 16])
    destination = socket.inet_ntoa(frame[ip_offset + 16 : ip_offset + 20])
    source_port = int.from_bytes(frame[udp_offset : udp_offset + 2], "big")
    destination_port = int.from_bytes(frame[udp_offset + 2 : udp_offset + 4], "big")
    udp_length = int.from_bytes(frame[udp_offset + 4 : udp_offset + 6], "big")
    payload_length = max(0, udp_length - 8)

    return {
        "source": source,
        "source_port": source_port,
        "destination": destination,
        "destination_port": destination_port,
        "udp_length": udp_length,
        "length": payload_length,
    }


def _find_ipv4_udp_offset(frame: bytes) -> int | None:
    candidates: list[int] = []
    if len(frame) >= 14:
        ethertype = int.from_bytes(frame[12:14], "big")
        if ethertype == 0x0800:
            candidates.append(14)
        if ethertype == 0x8100 and len(frame) >= 18 and int.from_bytes(frame[16:18], "big") == 0x0800:
            candidates.append(18)

    # Loopback and cooked captures are not always Ethernet II. Scan the small
    # link-layer prefix for an IPv4/UDP header so namespace-local traffic can
    # still be used as independent evidence.
    candidates.extend(range(0, min(32, len(frame))))
    seen: set[int] = set()
    for offset in candidates:
        if offset in seen:
            continue
        seen.add(offset)
        if _looks_like_ipv4_udp(frame, offset):
            return offset
    return None


def _looks_like_ipv4_udp(frame: bytes, offset: int) -> bool:
    if len(frame) < offset + 20:
        return False
    version_ihl = frame[offset]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(frame) < offset + ihl + 8:
        return False
    total_length = int.from_bytes(frame[offset + 2 : offset + 4], "big")
    if total_length < ihl + 8 or total_length > len(frame) - offset:
        return False
    return frame[offset + 9] == 17


if __name__ == "__main__":
    main()
