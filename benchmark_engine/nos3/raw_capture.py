from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import struct
import time


ETH_P_ALL = 0x0003
ETHERNET_LINKTYPE = 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture UDP or TCP packets as independent live benchmark evidence")
    parser.add_argument("--interface", required=True, help="Network interface to capture, such as br-xxxx")
    parser.add_argument("--pcap", type=Path, required=True, help="Output pcap path")
    parser.add_argument("--jsonl", type=Path, required=True, help="Output packet observation JSONL path")
    parser.add_argument("--ports", type=int, nargs="+", required=True, help="UDP ports to capture")
    parser.add_argument("--duration", type=float, required=True, help="Capture duration in seconds")
    parser.add_argument("--transport", choices=("udp", "tcp"), default="udp", help="Transport protocol to retain")
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

            observation = _parse_frame(frame, args.transport)
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


def _parse_frame(frame: bytes, transport: str) -> dict[str, object] | None:
    ip_offset = _find_ipv4_offset(frame, protocol=17 if transport == "udp" else 6)
    if ip_offset is None:
        return None

    version_ihl = frame[ip_offset]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or ihl < 20:
        return None

    protocol = frame[ip_offset + 9]
    expected_protocol = 17 if transport == "udp" else 6
    if protocol != expected_protocol:
        return None

    transport_offset = ip_offset + ihl
    minimum_header = 8 if transport == "udp" else 20
    if len(frame) < transport_offset + minimum_header:
        return None

    source = socket.inet_ntoa(frame[ip_offset + 12 : ip_offset + 16])
    destination = socket.inet_ntoa(frame[ip_offset + 16 : ip_offset + 20])
    source_port = int.from_bytes(frame[transport_offset : transport_offset + 2], "big")
    destination_port = int.from_bytes(frame[transport_offset + 2 : transport_offset + 4], "big")
    if transport == "udp":
        transport_length = int.from_bytes(frame[transport_offset + 4 : transport_offset + 6], "big")
        header_length = 8
        payload_length = max(0, transport_length - header_length)
        payload_end = min(len(frame), transport_offset + header_length + payload_length)
    else:
        header_length = ((frame[transport_offset + 12] >> 4) & 0x0F) * 4
        if header_length < 20 or len(frame) < transport_offset + header_length:
            return None
        total_length = int.from_bytes(frame[ip_offset + 2 : ip_offset + 4], "big")
        payload_length = max(0, total_length - ihl - header_length)
        payload_end = min(len(frame), transport_offset + header_length + payload_length)
        transport_length = header_length + payload_length
    payload = frame[transport_offset + header_length : payload_end]

    observation: dict[str, object] = {
        "source": source,
        "source_port": source_port,
        "destination": destination,
        "destination_port": destination_port,
        "transport": transport,
        "transport_length": transport_length,
        "length": payload_length,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
    if len(payload) >= 6:
        stream_id = int.from_bytes(payload[0:2], "big")
        sequence_control = int.from_bytes(payload[2:4], "big")
        declared_data_length = int.from_bytes(payload[4:6], "big")
        observation.update(
            {
                "ccsds_stream_id": stream_id,
                "ccsds_apid": stream_id & 0x07FF,
                "ccsds_sequence_count": sequence_control & 0x3FFF,
                "ccsds_sequence_flags": (sequence_control >> 14) & 0x03,
                "ccsds_declared_data_length": declared_data_length,
                "ccsds_complete_packet": _is_complete_ccsds_packet(payload, stream_id, declared_data_length),
            }
        )
    return observation


def _is_complete_ccsds_packet(payload: bytes, stream_id: int, declared_data_length: int) -> bool:
    version = (stream_id >> 13) & 0x07
    return version == 0 and len(payload) == 6 + declared_data_length + 1


def _find_ipv4_offset(frame: bytes, *, protocol: int) -> int | None:
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
        if _looks_like_ipv4(frame, offset, protocol=protocol):
            return offset
    return None


def _looks_like_ipv4(frame: bytes, offset: int, *, protocol: int) -> bool:
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
    return frame[offset + 9] == protocol


if __name__ == "__main__":
    main()
