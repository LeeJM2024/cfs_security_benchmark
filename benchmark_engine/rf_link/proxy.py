from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import random
import socket
import threading
import time
from pathlib import Path

from benchmark_engine.core.scenario import Scenario, load_scenario


Direction = str
IP_TRANSPARENT = 19


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int

    @classmethod
    def parse(cls, value: str) -> "Endpoint":
        if ":" not in value:
            raise argparse.ArgumentTypeError("endpoint must use host:port")
        host, port = value.rsplit(":", 1)
        return cls(host=host, port=int(port))

    def as_tuple(self) -> tuple[str, int]:
        return self.host, self.port


class EventLog:
    def __init__(self, path: Path | None):
        self.path = path
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, **fields: object) -> None:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        line = json.dumps(payload, sort_keys=True)
        with self._lock:
            if self.path:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            print(line, flush=True)


class RfLinkProxy:
    def __init__(
        self,
        scenario: Scenario,
        listen: Endpoint,
        target: Endpoint,
        reverse_listen: Endpoint | None,
        log: EventLog,
        seed: int | None,
        socket_mark: int | None = None,
        traffic_direction: Direction = "uplink",
        transparent_listen: bool = False,
    ):
        self.scenario = scenario
        self.listen = listen
        self.target = target
        self.reverse_listen = reverse_listen
        self.log = log
        self.random = random.Random(seed)
        self.socket_mark = socket_mark
        self.traffic_direction = traffic_direction
        self.transparent_listen = transparent_listen
        self.stop_event = threading.Event()
        self.attack = scenario.attack
        self.history: deque[bytes] = deque(maxlen=int(self.attack.get("history_size", 64)))
        self.reorder_buffer: deque[tuple[int, bytes]] = deque()
        self._reorder_ordinal = 0

    def run(self, duration_seconds: float | None = None) -> None:
        self.log.write(
            "scenario_start",
            scenario_id=self.scenario.id,
            scenario_name=self.scenario.name,
            attack_type=self.scenario.attack_type,
            listen=f"{self.listen.host}:{self.listen.port}",
            target=f"{self.target.host}:{self.target.port}",
            socket_mark=self.socket_mark,
            traffic_direction=self.traffic_direction,
        )

        threads = [
            threading.Thread(
                target=self._forward_loop,
                args=(self.traffic_direction, self.listen, self.target),
                daemon=True,
            )
        ]
        if self.reverse_listen:
            threads.append(
                threading.Thread(target=self._forward_loop, args=("downlink", self.reverse_listen, self.listen), daemon=True)
            )

        for thread in threads:
            thread.start()

        if self.attack.get("type") == "flood":
            threads.append(threading.Thread(target=self._flood_loop, daemon=True))
            threads[-1].start()

        if self.attack.get("type") == "fabricate":
            threads.append(threading.Thread(target=self._fabricate_loop, daemon=True))
            threads[-1].start()

        try:
            if duration_seconds is None:
                while not self.stop_event.is_set():
                    time.sleep(0.2)
            else:
                deadline = time.monotonic() + duration_seconds
                while time.monotonic() < deadline and not self.stop_event.is_set():
                    time.sleep(0.2)
        except KeyboardInterrupt:
            self.log.write("interrupted")
        finally:
            self.stop_event.set()
            for thread in threads:
                thread.join(timeout=1)
            self.log.write("scenario_stop", scenario_id=self.scenario.id)

    def _forward_loop(self, direction: Direction, source: Endpoint, destination: Endpoint) -> None:
        sock = self._make_udp_socket(marked=False)
        if self.transparent_listen:
            sock.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(source.as_tuple())
        sock.settimeout(0.5)
        self.log.write("socket_bound", direction=direction, listen=f"{source.host}:{source.port}")

        send_sock = self._make_udp_socket(marked=True)

        with sock, send_sock:
            while not self.stop_event.is_set():
                try:
                    packet, sender = sock.recvfrom(65535)
                except socket.timeout:
                    self._flush_reorder(send_sock, destination, direction=direction, force=False)
                    continue

                self.history.append(packet)
                self.log.write(
                    "packet_received",
                    direction=direction,
                    bytes=len(packet),
                    sender=f"{sender[0]}:{sender[1]}",
                    **_packet_fingerprint(packet),
                )

                for outgoing in self._apply_attack(packet, direction):
                    self._send_packet(send_sock, outgoing, destination, direction)

            # A partial reorder window must not turn an ordering test into an
            # unintended packet-drop test when the proxy is stopped.
            self._flush_reorder(send_sock, destination, direction=direction, force=True)

    def _apply_attack(self, packet: bytes, direction: Direction) -> list[bytes]:
        attack_type = self.scenario.attack_type
        affected_direction = str(self.attack.get("direction", "uplink"))
        if affected_direction != "both" and direction != affected_direction:
            return [packet]

        if attack_type == "observe":
            return [packet]
        if attack_type == "drop":
            return [] if self._should_hit() else [packet]
        if attack_type == "delay":
            delay_ms = float(self.attack.get("delay_ms", 1000))
            time.sleep(delay_ms / 1000.0)
            return [packet]
        if attack_type == "bit_flip":
            return [self._bit_flip(packet)]
        if attack_type == "replay":
            repeats = int(self.attack.get("repeats", 1))
            spacing_ms = float(self.attack.get("spacing_ms", 0))
            packets = [packet]
            if self._should_hit():
                for _ in range(repeats):
                    if spacing_ms:
                        time.sleep(spacing_ms / 1000.0)
                    packets.append(packet)
                self.log.write("packet_replayed", direction=direction, repeats=repeats)
            return packets
        if attack_type == "reorder":
            self._reorder_ordinal += 1
            self.reorder_buffer.append((self._reorder_ordinal, packet))
            size = int(self.attack.get("window_size", 4))
            if len(self.reorder_buffer) < size:
                self.log.write("packet_buffered_for_reorder", direction=direction, buffer_size=len(self.reorder_buffer))
                return []
            packets = list(self.reorder_buffer)
            self.reorder_buffer.clear()
            return self._reorder_packets(packets, direction=direction, force=False)

        return [packet]

    def _send_packet(self, sock: socket.socket, packet: bytes, destination: Endpoint, direction: Direction) -> None:
        sock.sendto(packet, destination.as_tuple())
        self.log.write(
            "packet_forwarded",
            direction=direction,
            bytes=len(packet),
            destination=f"{destination.host}:{destination.port}",
            **_packet_fingerprint(packet),
        )

    def _flood_loop(self) -> None:
        rate = float(self.attack.get("rate_per_second", 20))
        payload_size = int(self.attack.get("payload_size", 64))
        duration = float(self.attack.get("flood_duration_seconds", 10))
        interval = 1.0 / max(rate, 1.0)
        deadline = time.monotonic() + duration
        sock = self._make_udp_socket(marked=True)

        with sock:
            while time.monotonic() < deadline and not self.stop_event.is_set():
                payload = self.random.randbytes(payload_size)
                sock.sendto(payload, self.target.as_tuple())
                self.log.write(
                    "packet_flooded",
                    direction=self.traffic_direction,
                    bytes=len(payload),
                    destination=f"{self.target.host}:{self.target.port}",
                )
                time.sleep(interval)

    def _fabricate_loop(self) -> None:
        interval_ms = float(self.attack.get("interval_ms", 1000))
        payload_hex = str(self.attack.get("payload_hex", ""))
        payload_text = str(self.attack.get("payload_text", ""))
        count = int(self.attack.get("count", 1))
        payload = bytes.fromhex(payload_hex) if payload_hex else payload_text.encode("utf-8")
        sock = self._make_udp_socket(marked=True)

        with sock:
            for _ in range(count):
                if self.stop_event.is_set():
                    break
                sock.sendto(payload, self.target.as_tuple())
                self.log.write(
                    "packet_fabricated",
                    direction=self.traffic_direction,
                    bytes=len(payload),
                    destination=f"{self.target.host}:{self.target.port}",
                )
                time.sleep(interval_ms / 1000.0)

    def _flush_reorder(self, sock: socket.socket, destination: Endpoint, direction: Direction, force: bool) -> None:
        if self.scenario.attack_type != "reorder" or not self.reorder_buffer:
            return
        if not force and len(self.reorder_buffer) < int(self.attack.get("window_size", 4)):
            return
        packets = list(self.reorder_buffer)
        self.reorder_buffer.clear()
        for packet in self._reorder_packets(packets, direction=direction, force=force):
            self._send_packet(sock, packet, destination, direction)

    def _reorder_packets(self, packets: list[tuple[int, bytes]], *, direction: Direction, force: bool) -> list[bytes]:
        input_ordinals = [ordinal for ordinal, _ in packets]
        self.random.shuffle(packets)
        output_ordinals = [ordinal for ordinal, _ in packets]
        if len(output_ordinals) > 1 and output_ordinals == input_ordinals:
            packets = packets[1:] + packets[:1]
            output_ordinals = [ordinal for ordinal, _ in packets]
        self.log.write(
            "packets_reordered",
            direction=direction,
            count=len(packets),
            force=force,
            input_ordinals=input_ordinals,
            output_ordinals=output_ordinals,
            order_changed=output_ordinals != input_ordinals,
        )
        return [packet for _, packet in packets]

    def _should_hit(self) -> bool:
        probability = float(self.attack.get("probability", 1.0))
        return self.random.random() <= probability

    def _bit_flip(self, packet: bytes) -> bytes:
        if not packet:
            return packet
        offset = int(self.attack.get("offset", -1))
        if offset < 0:
            offset = self.random.randrange(0, len(packet))
        bit = int(self.attack.get("bit", self.random.randrange(0, 8)))
        mutated = bytearray(packet)
        mutated[offset % len(mutated)] ^= 1 << (bit % 8)
        self.log.write("packet_bit_flipped", offset=offset % len(mutated), bit=bit % 8, bytes=len(mutated))
        return bytes(mutated)

    def _make_udp_socket(self, marked: bool) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if marked and self.socket_mark is not None:
            if not hasattr(socket, "SO_MARK"):
                raise RuntimeError("SO_MARK is not available on this platform")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, self.socket_mark)
            self.log.write("socket_mark_set", mark=self.socket_mark)
        return sock


def _packet_fingerprint(packet: bytes) -> dict[str, int | str]:
    fingerprint: dict[str, int | str] = {
        "payload_sha256": hashlib.sha256(packet).hexdigest(),
    }
    if len(packet) >= 6:
        stream_id = int.from_bytes(packet[0:2], "big")
        sequence_control = int.from_bytes(packet[2:4], "big")
        fingerprint.update(
            {
                "ccsds_stream_id": stream_id,
                "ccsds_apid": stream_id & 0x07FF,
                "ccsds_sequence_count": sequence_control & 0x3FFF,
                "ccsds_sequence_flags": (sequence_control >> 14) & 0x03,
                "ccsds_declared_data_length": int.from_bytes(packet[4:6], "big"),
            }
        )
    return fingerprint


def main() -> None:
    parser = argparse.ArgumentParser(description="RF-link UDP attack proxy for cFS/NOS3 benchmark scenarios")
    parser.add_argument("--scenario", required=True, help="Path to a scenario YAML/JSON file")
    parser.add_argument("--listen", type=Endpoint.parse, required=True, help="Proxy listen endpoint, host:port")
    parser.add_argument("--target", type=Endpoint.parse, required=True, help="Destination endpoint, host:port")
    parser.add_argument("--reverse-listen", type=Endpoint.parse, help="Optional downlink listen endpoint, host:port")
    parser.add_argument("--duration", type=float, help="Stop automatically after this many seconds")
    parser.add_argument("--seed", type=int, default=7, help="Deterministic seed for probabilistic attacks")
    parser.add_argument("--socket-mark", type=lambda value: int(value, 0), help="Linux SO_MARK value for proxy-originated packets")
    parser.add_argument("--transparent-listen", action="store_true", help="Receive packets redirected with TPROXY")
    parser.add_argument("--traffic-direction", choices=("uplink", "downlink"), default="uplink", help="Direction represented by this proxy instance")
    parser.add_argument("--log", type=Path, help="JSONL event log path")
    args = parser.parse_args()

    scenario = load_scenario(args.scenario)
    proxy = RfLinkProxy(
        scenario=scenario,
        listen=args.listen,
        target=args.target,
        reverse_listen=args.reverse_listen,
        log=EventLog(args.log),
        seed=args.seed,
        socket_mark=args.socket_mark,
        traffic_direction=args.traffic_direction,
        transparent_listen=args.transparent_listen,
    )
    proxy.run(duration_seconds=args.duration)


if __name__ == "__main__":
    main()
