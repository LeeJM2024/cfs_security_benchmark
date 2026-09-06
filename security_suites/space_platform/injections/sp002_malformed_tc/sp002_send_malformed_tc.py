#!/usr/bin/env python3
"""
SP002 malformed TC packet builder/sender for NOS3/cFS.

This tool intentionally creates raw UDP command datagrams for CI/CI_LAB.
It does not use COSMOS/OpenC3 command construction because SP002 needs
packets that normal ground tooling would refuse or normalize.
"""

import argparse
import binascii
import json
import os
import random
import signal
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence


DEFAULT_CI_HOST = os.environ.get("SP002_CI_HOST", "127.0.0.1")
DEFAULT_CI_PORT = int(os.environ.get("SP002_CI_PORT", "5012"))


def discover_to_lab_ip(ci_host: str, ci_port: int) -> str:
    """Return the local container IP FSW should use for TO_LAB telemetry.

    The sender usually runs inside the OpenC3 operator container.  A UDP
    connect does not send traffic, but it asks the kernel which source IP
    would be used to reach the FSW container.  That is the address TO_LAB
    must send telemetry back to.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((ci_host, ci_port))
            local_ip = sock.getsockname()[0]
            if local_ip and not local_ip.startswith("127."):
                return local_ip
    except OSError:
        pass

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            local_ip = info[4][0]
            if local_ip and not local_ip.startswith("127."):
                return local_ip
    except OSError:
        pass

    return "127.0.0.1"


_ENV_TO_LAB_IP = os.environ.get("SP002_TO_LAB_IP", "").strip()
DEFAULT_TO_LAB_IP = _ENV_TO_LAB_IP or discover_to_lab_ip(DEFAULT_CI_HOST, DEFAULT_CI_PORT)

CFE_CMD_HDR_LEN = 8
CI_LAB_MAX_INGEST = 768

SEQ_STANDALONE = 0xC000
SEQ_FIRST = 0x4001
SEQ_CONTINUATION = 0x0002
SEQ_LAST = 0x8003


def u8(value: int) -> bytes:
    return struct.pack("<B", value & 0xFF)


def i8(value: int) -> bytes:
    return struct.pack("<b", max(-128, min(127, value)))


def u16(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def i16(value: int) -> bytes:
    value = max(-32768, min(32767, value))
    return struct.pack("<h", value)


def u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def path64(value: str, *, terminate: bool = True, fill: int = 0) -> bytes:
    raw = value.encode("ascii", errors="replace")
    if terminate:
        raw = raw[:63] + b"\x00"
    else:
        raw = raw[:64]
    return raw.ljust(64, bytes([fill & 0xFF]))


def fixed_ascii(value: str, size: int, *, terminate: bool = True, fill: int = 0) -> bytes:
    raw = value.encode("ascii", errors="replace")
    if terminate:
        raw = raw[: max(0, size - 1)] + b"\x00"
    else:
        raw = raw[:size]
    return raw.ljust(size, bytes([fill & 0xFF]))


def pattern(size: int, seed: int = 0x42) -> bytes:
    return bytes(((seed + i * 37) & 0xFF) for i in range(size))


def cfe_checksum(packet: bytes) -> int:
    value = 0xFF
    for byte in packet:
        value ^= byte
    return value & 0xFF


def command_packet(
    mid: int,
    fc: int,
    payload: bytes = b"",
    *,
    checksum: Optional[int] = None,
    seq: int = SEQ_STANDALONE,
    declared_total_len: Optional[int] = None,
    stream_id_override: Optional[int] = None,
    length_override: Optional[int] = None,
) -> bytes:
    total_len = CFE_CMD_HDR_LEN + len(payload) if declared_total_len is None else declared_total_len
    length_field = (total_len - 7) & 0xFFFF if length_override is None else length_override & 0xFFFF
    stream_id = mid if stream_id_override is None else stream_id_override & 0xFFFF

    pkt = bytearray()
    pkt.extend(struct.pack(">H", stream_id & 0xFFFF))
    pkt.extend(struct.pack(">H", seq & 0xFFFF))
    pkt.extend(struct.pack(">H", length_field))
    pkt.extend(struct.pack("BB", fc & 0xFF, 0))
    pkt.extend(payload)

    pkt[7] = cfe_checksum(pkt) if checksum is None else checksum & 0xFF
    return bytes(pkt)


def mutate(packet: bytes, *, drop_tail: int = 0, append: bytes = b"", checksum: Optional[int] = None) -> bytes:
    data = bytearray(packet)
    if drop_tail > 0:
        data = data[:-drop_tail]
    if append:
        data.extend(append)
    if checksum is not None and len(data) >= CFE_CMD_HDR_LEN:
        data[7] = checksum & 0xFF
    return bytes(data)


PayloadFactory = Callable[[], bytes]


class CommandSpec:
    def __init__(self, name: str, target: str, mid: int, fc: int, payload: PayloadFactory, risk: str, effect: str) -> None:
        self.name = name
        self.target = target
        self.mid = mid
        self.fc = fc
        self.payload = payload
        self.risk = risk
        self.effect = effect

    def payload_bytes(self) -> bytes:
        return self.payload()


class Profile:
    def __init__(
        self,
        profile_id: str,
        title: str,
        category: str,
        target: str,
        tags: Sequence[str],
        risk: str,
        suite: str,
        expected_focus: str,
        builder: Callable[[], bytes],
    ) -> None:
        self.profile_id = profile_id
        self.title = title
        self.category = category
        self.target = target
        self.tags = tags
        self.risk = risk
        self.suite = suite
        self.expected_focus = expected_focus
        self.builder = builder

    def packet(self) -> bytes:
        return self.builder()

    def to_json(self, packet: Optional[bytes] = None) -> Dict[str, object]:
        pkt = self.packet() if packet is None else packet
        return {
            "profile_id": self.profile_id,
            "title": self.title,
            "category": self.category,
            "target": self.target,
            "tags": list(self.tags),
            "risk": self.risk,
            "suite": self.suite,
            "expected_focus": self.expected_focus,
            "packet_len": len(pkt),
            "checksum_result": cfe_checksum(pkt) if len(pkt) >= CFE_CMD_HDR_LEN else None,
            "hex": pkt.hex(),
        }


def noop() -> bytes:
    return b""


def ds_state(state: int = 1, table_index: int = 0) -> bytes:
    return u16(state) + u16(table_index)


def lc_state(state: int = 1) -> bytes:
    return u16(state) + u16(0)


def lc_ap_state(ap_number: int = 0, state: int = 1) -> bytes:
    return u16(ap_number) + u16(state)


def sc_rts(rts_id: int = 1) -> bytes:
    return u16(rts_id) + u16(0)


def sch_entry(slot: int = 1, entry: int = 0) -> bytes:
    return u16(slot) + u16(entry)


def sch_group(group: int = 1, mask: int = 1) -> bytes:
    return u32(((group & 0xFF) << 24) | (mask & 0x00FFFFFF))


def fm_path(path: str = "/cf/sp002.tmp", *, terminate: bool = True) -> bytes:
    return path64(path, terminate=terminate)


def fm_delete_all(path: str = "/cf/sp002_dir") -> bytes:
    return path64(path) + path64("*")


def fm_perm(path: str = "/cf/sp002.tmp", mode: int = 0o644) -> bytes:
    return path64(path) + u32(mode)


def to_ip(ip: str = "127.0.0.1") -> bytes:
    return fixed_ascii(ip, 16)


def to_stream(stream_mid: int = 0x0801) -> bytes:
    return struct.pack(">H", stream_mid & 0xFFFF)


def adcs_mode(mode: int = 1) -> bytes:
    return u8(mode)


def adcs_momentum(state: int = 1) -> bytes:
    return u8(state)


def adcs_quat(value: float = 9999.0) -> bytes:
    return struct.pack("<dddd", value, -value, value, -value)


def device_cfg(cfg: int = 0xDEADBEEF) -> bytes:
    return u32(cfg)


def eps_switch(switch: int = 0, state: int = 0xAA) -> bytes:
    return u8(switch) + u8(state)


def rw_cmd(wheel: int = 0, torque: int = 100) -> bytes:
    return u8(wheel) + i16(torque)


def torquer_percent(trq: int = 0, direction: int = 1, percent: int = 50) -> bytes:
    return u8(trq) + u8(direction) + u8(percent)


def torquer_all(direction: int = 1, percent: int = 50) -> bytes:
    return bytes([direction & 0xFF, percent & 0xFF, direction & 0xFF, percent & 0xFF, direction & 0xFF, percent & 0xFF])


def thruster_percentage(thruster: int = 0, percent: int = 50) -> bytes:
    return u8(thruster) + u8(percent)


def radio_proximity(scid: int = 1, size: int = 128) -> bytes:
    return u16(scid) + pattern(size, 0x31)


def novatel_log(log_type: int = 1, period_option: int = 1) -> bytes:
    return u8(log_type) + u8(period_option)


def novatel_unlog(log_type: int = 1) -> bytes:
    return u8(log_type)


def es_app_name(name: str = "DS") -> bytes:
    return fixed_ascii(name, 20)


COMMANDS: Dict[str, CommandSpec] = {}


def add_cmd(name: str, target: str, mid: int, fc: int, payload: PayloadFactory, risk: str, effect: str) -> None:
    COMMANDS[name] = CommandSpec(name, target, mid, fc, payload, risk, effect)


def register_commands() -> None:
    add_cmd("cfe_es_noop", "CFE_ES", 0x1806, 0, noop, "safe", "baseline cFE ES command parser")
    add_cmd("cfe_es_stop_ds", "CFE_ES", 0x1806, 5, lambda: es_app_name("DS"), "hazardous", "stop a loaded app")

    add_cmd("fm_noop", "FM", 0x188C, 0, noop, "safe", "baseline file manager command parser")
    add_cmd("fm_create_dir", "FM", 0x188C, 12, lambda: fm_path("/cf/sp002_safe_dir"), "safe", "filesystem path handling")
    add_cmd("fm_delete_file", "FM", 0x188C, 5, lambda: fm_path("/cf/sp002_delete_me.tmp"), "hazardous", "file deletion")
    add_cmd("fm_delete_all", "FM", 0x188C, 7, lambda: fm_delete_all("/cf/sp002_delete_all"), "hazardous", "bulk deletion")
    add_cmd("fm_set_perm", "FM", 0x188C, 19, lambda: fm_perm("/cf/sp002_perm.tmp", 0o777), "hazardous", "file permission changes")

    add_cmd("ds_noop", "DS", 0x18BB, 0, noop, "safe", "baseline data storage command parser")
    add_cmd("ds_set_app_state", "DS", 0x18BB, 2, lambda: ds_state(1, 0), "safe", "DS global enable state")
    add_cmd("ds_set_dest_state", "DS", 0x18BB, 7, lambda: ds_state(0, 1), "safe", "DS destination state")

    add_cmd("lc_noop", "LC", 0x18A4, 0, noop, "safe", "baseline limit checker command parser")
    add_cmd("lc_set_lc_state", "LC", 0x18A4, 2, lambda: lc_state(1), "safe", "LC global state")
    add_cmd("lc_set_ap_state", "LC", 0x18A4, 3, lambda: lc_ap_state(0, 1), "safe", "LC actionpoint state")

    add_cmd("sc_noop", "SC", 0x18A9, 0, noop, "safe", "baseline stored command parser")
    add_cmd("sc_start_rts", "SC", 0x18A9, 4, lambda: sc_rts(1), "hazardous", "start RTS")
    add_cmd("sc_disable_rts", "SC", 0x18A9, 6, lambda: sc_rts(1), "safe", "disable RTS")

    add_cmd("sch_noop", "SCH", 0x1895, 0, noop, "safe", "baseline scheduler parser")
    add_cmd("sch_disable_entry", "SCH", 0x1895, 3, lambda: sch_entry(1, 0), "safe", "disable scheduled entry")
    add_cmd("sch_disable_group", "SCH", 0x1895, 5, lambda: sch_group(1, 1), "safe", "disable scheduled group")

    add_cmd("to_lab_noop", "TO_LAB", 0x18E8, 0, noop, "safe", "baseline telemetry output parser")
    add_cmd("to_lab_output_enable", "TO_LAB", 0x18E8, 2, lambda: to_ip(DEFAULT_TO_LAB_IP), "safe", "output destination handling")
    add_cmd("to_lab_remove_pkt", "TO_LAB", 0x18E8, 4, lambda: to_stream(0x0801), "safe", "telemetry subscription removal")
    add_cmd("to_lab_remove_all", "TO_LAB", 0x18E8, 5, noop, "hazardous", "remove all telemetry subscriptions")

    add_cmd("adcs_set_mode", "GENERIC_ADCS", 0x1940, 2, lambda: adcs_mode(1), "safe", "ADCS mode state")
    add_cmd("adcs_momentum", "GENERIC_ADCS", 0x1940, 8, lambda: adcs_momentum(1), "safe", "momentum management")
    add_cmd("adcs_quat", "GENERIC_ADCS", 0x1940, 9, lambda: adcs_quat(9999.0), "hazardous", "attitude quaternion command")

    add_cmd("thruster_enable", "GENERIC_THRUSTER", 0x18EA, 2, noop, "hazardous", "thruster enable")
    add_cmd("thruster_disable", "GENERIC_THRUSTER", 0x18EA, 3, noop, "safe", "thruster disable")
    add_cmd("thruster_percentage", "GENERIC_THRUSTER", 0x18EA, 4, lambda: thruster_percentage(0, 50), "hazardous", "thruster percentage")

    add_cmd("radio_config", "GENERIC_RADIO", 0x1930, 2, lambda: device_cfg(0x01020304), "safe", "radio configuration")
    add_cmd("radio_proximity", "GENERIC_RADIO", 0x1930, 3, lambda: radio_proximity(1, 128), "safe", "proximity forwarding")

    add_cmd("novatel_enable", "NOVATEL_OEM615", 0x1870, 2, noop, "safe", "GNSS device enable")
    add_cmd("novatel_disable", "NOVATEL_OEM615", 0x1870, 3, noop, "safe", "GNSS device disable")
    add_cmd("novatel_log", "NOVATEL_OEM615", 0x1870, 4, lambda: novatel_log(1, 1), "safe", "GNSS log stream")
    add_cmd("novatel_unlog", "NOVATEL_OEM615", 0x1870, 5, lambda: novatel_unlog(1), "safe", "GNSS log removal")
    add_cmd("novatel_unlogall", "NOVATEL_OEM615", 0x1870, 6, noop, "hazardous", "remove all GNSS logs")
    add_cmd("novatel_serialconfig", "NOVATEL_OEM615", 0x1870, 7, noop, "hazardous", "GNSS serial configuration")

    add_cmd("imu_enable", "GENERIC_IMU", 0x1925, 2, noop, "safe", "IMU enable")
    add_cmd("imu_disable", "GENERIC_IMU", 0x1925, 3, noop, "safe", "IMU disable")
    add_cmd("imu_config", "GENERIC_IMU", 0x1925, 4, lambda: device_cfg(0x01020304), "safe", "IMU configuration")
    add_cmd("mag_enable", "GENERIC_MAG", 0x192A, 2, noop, "safe", "magnetometer enable")
    add_cmd("mag_disable", "GENERIC_MAG", 0x192A, 3, noop, "safe", "magnetometer disable")
    add_cmd("css_enable", "GENERIC_CSS", 0x1910, 2, noop, "safe", "coarse sun sensor enable")
    add_cmd("css_disable", "GENERIC_CSS", 0x1910, 3, noop, "safe", "coarse sun sensor disable")
    add_cmd("fss_enable", "GENERIC_FSS", 0x1920, 2, noop, "safe", "fine sun sensor enable")
    add_cmd("fss_disable", "GENERIC_FSS", 0x1920, 3, noop, "safe", "fine sun sensor disable")
    add_cmd("star_tracker_enable", "GENERIC_STAR_TRACKER", 0x1935, 2, noop, "safe", "star tracker enable")
    add_cmd("star_tracker_disable", "GENERIC_STAR_TRACKER", 0x1935, 3, noop, "safe", "star tracker disable")
    add_cmd("star_tracker_config", "GENERIC_STAR_TRACKER", 0x1935, 4, lambda: device_cfg(0x01020304), "safe", "star tracker configuration")

    add_cmd("eps_switch", "GENERIC_EPS", 0x191A, 2, lambda: eps_switch(0, 0xAA), "safe", "EPS switch state")
    add_cmd("rw_set_torque", "GENERIC_RW", 0x1992, 3, lambda: rw_cmd(0, 100), "hazardous", "reaction wheel torque")
    add_cmd("rw_enable", "GENERIC_RW", 0x1992, 4, lambda: rw_cmd(0, 0), "hazardous", "reaction wheel enable")
    add_cmd("rw_disable", "GENERIC_RW", 0x1992, 5, lambda: rw_cmd(0, 0), "safe", "reaction wheel disable")
    add_cmd("torquer_enable", "GENERIC_TORQUER", 0x193A, 2, noop, "hazardous", "magnetorquer enable")
    add_cmd("torquer_disable", "GENERIC_TORQUER", 0x193A, 3, noop, "safe", "magnetorquer disable")
    add_cmd("torquer_percent", "GENERIC_TORQUER", 0x193A, 4, lambda: torquer_percent(0, 1, 50), "hazardous", "magnetorquer duty cycle")
    add_cmd("torquer_all_percent", "GENERIC_TORQUER", 0x193A, 5, lambda: torquer_all(1, 50), "hazardous", "all magnetorquer duty cycles")


def base_packet(spec: CommandSpec) -> bytes:
    return command_packet(spec.mid, spec.fc, spec.payload_bytes())


def add_profile(
    profiles: List[Profile],
    profile_id: str,
    title: str,
    category: str,
    target: str,
    tags: Sequence[str],
    risk: str,
    expected_focus: str,
    builder: Callable[[], bytes],
    suite: str = "quick",
) -> None:
    profiles.append(Profile(profile_id, title, category, target, tuple(tags), risk, suite, expected_focus, builder))


def make_catalog() -> List[Profile]:
    register_commands()
    profiles: List[Profile] = []

    ci_cases = [
        ("ci_short_1", "One-byte UDP datagram", b"\x18", "CI_LAB short datagram rejection"),
        ("ci_short_7", "Seven-byte command fragment", b"\x18\x06\xc0\x00\x00\x01\x00", "CI_LAB short command header rejection"),
        ("ci_random_7", "Random seven-byte fragment", pattern(7, 0xA0), "CI_LAB short random input rejection"),
        ("ci_random_8", "Random minimum-size command", pattern(8, 0x21), "minimum datagram parser robustness"),
        ("ci_random_max_ingest", "Random max-ingest datagram", pattern(CI_LAB_MAX_INGEST, 0x51), "CI_LAB max accepted datagram robustness"),
        (
            "ci_truncated_oversize_769",
            "One byte above CI_LAB_MAX_INGEST, truncated by receive buffer",
            pattern(CI_LAB_MAX_INGEST + 1, 0x61),
            "oversized UDP is read through the 768-byte CI_LAB buffer and then rejected by SB validation",
        ),
        (
            "ci_truncated_oversize_1500",
            "MTU-sized UDP datagram, truncated by receive buffer",
            pattern(1500, 0x71),
            "oversized UDP is read through the 768-byte CI_LAB buffer and then rejected by SB validation",
        ),
    ]
    for pid, title, data, focus in ci_cases:
        target = "CI_LAB" if len(data) < CFE_CMD_HDR_LEN else "CFE_SB"
        tags = ("raw_udp", "ci_length") if target == "CI_LAB" else ("raw_udp", "sb_validation")
        add_profile(profiles, pid, title, "ci_parser", target, tags, "safe", focus, lambda data=data: data)

    ccsds_anchor = COMMANDS["fm_noop"]
    header_cases = [
        ("ccsds_invalid_version_bits", "Non-zero CCSDS version bits", 0xF806, None, None, "CCSDS version validation"),
        ("ccsds_seq_first_only", "First-segment sequence flag", ccsds_anchor.mid, SEQ_FIRST, None, "segmentation flag handling"),
        ("ccsds_seq_continuation", "Continuation segment sequence flag", ccsds_anchor.mid, SEQ_CONTINUATION, None, "segmentation flag handling"),
        ("ccsds_seq_last_only", "Last-segment sequence flag", ccsds_anchor.mid, SEQ_LAST, None, "segmentation flag handling"),
        ("ccsds_length_zero", "Declared length field zero", ccsds_anchor.mid, None, 0, "primary-header length lower bound"),
        ("ccsds_length_max", "Declared length field 0xFFFF", ccsds_anchor.mid, None, 0xFFFF, "primary-header length upper bound"),
        ("ccsds_length_oversize_declared", "Declared length above CI payload", ccsds_anchor.mid, None, 0x0300, "declared/actual length mismatch"),
        ("ccsds_all_zero_header", "All-zero command-sized datagram", 0, 0, 0, "zeroed parser input"),
    ]
    for pid, title, mid, seq, length_override, focus in header_cases:
        def build(pid=pid, mid=mid, seq=seq, length_override=length_override) -> bytes:
            if pid == "ccsds_all_zero_header":
                return b"\x00" * CFE_CMD_HDR_LEN
            return command_packet(
                ccsds_anchor.mid,
                ccsds_anchor.fc,
                b"",
                stream_id_override=mid,
                seq=SEQ_STANDALONE if seq is None else seq,
                length_override=length_override,
            )

        target = "FM" if pid.startswith("ccsds_seq_") else "CFE_SB"
        add_profile(profiles, pid, title, "ccsds_header", target, ("ccsds", "header"), "safe", focus, build)

    for spec in COMMANDS.values():
        valid = lambda spec=spec: base_packet(spec)
        add_profile(
            profiles,
            f"{spec.name}_valid_shape",
            f"{spec.name}: valid-shape control packet",
            "valid_shape",
            spec.target,
            ("control", "baseline_shape"),
            spec.risk,
            f"positive parser control for {spec.effect}",
            valid,
            suite="matrix",
        )

        add_profile(
            profiles,
            f"{spec.name}_bad_checksum",
            f"{spec.name}: invalid checksum",
            "command_handler",
            spec.target,
            ("checksum", "command_handler"),
            "safe",
            "command checksum rejection before handler side effect",
            lambda spec=spec: mutate(base_packet(spec), checksum=(base_packet(spec)[7] ^ 0x5A)),
            suite="matrix",
        )

        add_profile(
            profiles,
            f"{spec.name}_invalid_fc",
            f"{spec.name}: unsupported function code",
            "command_handler",
            spec.target,
            ("function_code", "command_handler"),
            "safe",
            "invalid command-code error path",
            lambda spec=spec: command_packet(spec.mid, 0xFE, spec.payload_bytes()),
            suite="matrix",
        )

        add_profile(
            profiles,
            f"{spec.name}_truncated",
            f"{spec.name}: truncated command body",
            "command_handler",
            spec.target,
            ("length", "truncated"),
            "safe",
            "short actual packet against expected command struct",
            lambda spec=spec: mutate(base_packet(spec), drop_tail=max(1, min(4, len(spec.payload_bytes()) or 1))),
            suite="matrix",
        )

        add_profile(
            profiles,
            f"{spec.name}_extra_payload",
            f"{spec.name}: valid command plus trailing payload",
            "command_handler",
            spec.target,
            ("length", "extra_payload"),
            "safe",
            "extra bytes after expected command struct",
            lambda spec=spec: command_packet(spec.mid, spec.fc, spec.payload_bytes() + pattern(16, 0xB0)),
            suite="matrix",
        )

        add_profile(
            profiles,
            f"{spec.name}_declared_short",
            f"{spec.name}: declared length shorter than datagram",
            "command_handler",
            spec.target,
            ("length", "declared_short"),
            "safe",
            "declared length shorter than actual UDP datagram",
            lambda spec=spec: command_packet(spec.mid, spec.fc, spec.payload_bytes(), declared_total_len=CFE_CMD_HDR_LEN),
            suite="matrix",
        )

        add_profile(
            profiles,
            f"{spec.name}_declared_long",
            f"{spec.name}: declared length longer than datagram",
            "command_handler",
            spec.target,
            ("length", "declared_long"),
            "safe",
            "declared length longer than actual UDP datagram",
            lambda spec=spec: command_packet(spec.mid, spec.fc, spec.payload_bytes(), declared_total_len=CFE_CMD_HDR_LEN + len(spec.payload_bytes()) + 32),
            suite="matrix",
        )

    semantic_cases = [
        ("fm_create_dir_empty_path", COMMANDS["fm_create_dir"], fm_path(""), "empty filesystem path"),
        ("fm_create_dir_no_nul", COMMANDS["fm_create_dir"], fm_path("/cf/" + "A" * 80, terminate=False), "unterminated long path"),
        ("fm_delete_traversal_path", COMMANDS["fm_delete_file"], fm_path("/cf/../cpu1/core-cpu1"), "path traversal-like string"),
        ("fm_set_perm_extreme_mode", COMMANDS["fm_set_perm"], fm_perm("/cf/sp002_perm.tmp", 0xFFFFFFFF), "extreme permission mode"),
        ("ds_set_app_state_invalid", COMMANDS["ds_set_app_state"], ds_state(0xFFFF, 0), "invalid DS app enable state"),
        ("ds_set_dest_state_oob", COMMANDS["ds_set_dest_state"], ds_state(999, 0xFFFF), "out-of-range DS destination index/state"),
        ("lc_set_lc_state_invalid", COMMANDS["lc_set_lc_state"], lc_state(0xFFFF), "invalid LC global state"),
        ("lc_set_ap_state_oob", COMMANDS["lc_set_ap_state"], lc_ap_state(0xFFFF, 0xFFFF), "out-of-range LC actionpoint"),
        ("sc_start_rts_zero", COMMANDS["sc_start_rts"], sc_rts(0), "invalid RTS id zero"),
        ("sc_start_rts_oob", COMMANDS["sc_start_rts"], sc_rts(0xFFFF), "out-of-range RTS id"),
        ("sch_disable_entry_oob", COMMANDS["sch_disable_entry"], sch_entry(0xFFFF, 0xFFFF), "out-of-range schedule slot/entry"),
        ("sch_disable_group_no_selection", COMMANDS["sch_disable_group"], sch_group(0, 0), "no schedule group or multi-group selected"),
        ("to_lab_output_enable_no_nul", COMMANDS["to_lab_output_enable"], fixed_ascii("255.255.255.255X", 16, terminate=False), "unterminated output IP"),
        ("to_lab_remove_pkt_unknown", COMMANDS["to_lab_remove_pkt"], to_stream(0x1BEE), "remove unknown telemetry stream"),
        ("adcs_set_mode_invalid", COMMANDS["adcs_set_mode"], adcs_mode(0xFF), "invalid ADCS mode"),
        ("adcs_momentum_invalid", COMMANDS["adcs_momentum"], adcs_momentum(0xFF), "invalid momentum-management state"),
        ("adcs_quat_nanish_large", COMMANDS["adcs_quat"], adcs_quat(1.0e300), "extreme quaternion values"),
        ("thruster_percentage_oob", COMMANDS["thruster_percentage"], thruster_percentage(0xFF, 0xFF), "out-of-range thruster percentage"),
        ("radio_config_extreme", COMMANDS["radio_config"], device_cfg(0xFFFFFFFF), "extreme radio configuration word"),
        ("radio_proximity_large", COMMANDS["radio_proximity"], radio_proximity(0xFFFF, 512), "large proximity payload"),
        ("novatel_log_invalid", COMMANDS["novatel_log"], novatel_log(0xFF, 0xFF), "invalid GNSS log request"),
        ("novatel_unlog_invalid", COMMANDS["novatel_unlog"], novatel_unlog(0xFF), "invalid GNSS unlog request"),
        ("imu_config_extreme", COMMANDS["imu_config"], device_cfg(0xFFFFFFFF), "extreme IMU configuration"),
        ("star_tracker_config_extreme", COMMANDS["star_tracker_config"], device_cfg(0xFFFFFFFF), "extreme star tracker configuration"),
        ("eps_switch_invalid", COMMANDS["eps_switch"], eps_switch(0xFF, 0x55), "out-of-range EPS switch/state"),
        ("rw_set_torque_oob", COMMANDS["rw_set_torque"], rw_cmd(0xFF, 32767), "out-of-range RW torque/wheel"),
        ("rw_enable_oob", COMMANDS["rw_enable"], rw_cmd(0xFF, 0), "out-of-range RW wheel enable"),
        ("torquer_percent_oob", COMMANDS["torquer_percent"], torquer_percent(0xFF, 0xFF, 0xFF), "out-of-range torquer command"),
        ("torquer_all_percent_oob", COMMANDS["torquer_all_percent"], bytes([0xFF] * 6), "out-of-range all-torquer command"),
    ]
    for pid, spec, payload, focus in semantic_cases:
        suite = "matrix" if pid in {"to_lab_output_enable_no_nul", "lc_set_lc_state_invalid", "lc_set_ap_state_oob"} else "quick"
        add_profile(
            profiles,
            pid,
            f"{spec.target}: {focus}",
            "semantic_malformed",
            spec.target,
            ("semantic", "out_of_range"),
            "hazardous",
            focus,
            lambda spec=spec, payload=payload: command_packet(spec.mid, spec.fc, payload),
            suite=suite,
        )

    return profiles


def select_profiles(profiles: Sequence[Profile], names: Sequence[str], target: Optional[str], tags: Sequence[str], mode: str) -> List[Profile]:
    selected = list(profiles)
    if names:
        wanted = set(names)
        by_id = {profile.profile_id: profile for profile in selected}
        missing = sorted(wanted - set(by_id))
        if missing:
            raise SystemExit(f"Unknown profile(s): {', '.join(missing)}")
        selected = [by_id[name] for name in names]
    if target:
        selected = [p for p in selected if p.target.lower() == target.lower()]
    for tag in tags:
        selected = [p for p in selected if tag in p.tags or tag == p.category or tag == p.suite]
    if mode == "safe":
        selected = [p for p in selected if p.suite == "quick" and p.risk == "safe"]
    elif mode == "hazardous":
        selected = [p for p in selected if p.suite == "quick" and p.risk == "hazardous"]
    elif mode == "short-all":
        selected = [p for p in selected if p.suite == "quick"]
    elif mode == "all":
        pass
    else:
        raise SystemExit(f"Unknown mode: {mode}")
    return selected


def dump_profile(profile: Profile, out_dir: Path) -> Dict[str, object]:
    pkt = profile.packet()
    out_dir.mkdir(parents=True, exist_ok=True)
    bin_path = out_dir / f"{profile.profile_id}.bin"
    json_path = out_dir / f"{profile.profile_id}.json"
    bin_path.write_bytes(pkt)
    meta = profile.to_json(pkt)
    meta["bin_path"] = str(bin_path)
    meta["json_path"] = str(json_path)
    json_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return meta


def send_packet(packet: bytes, host: str, port: int, timeout: float) -> Dict[str, object]:
    started = time.time()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sent = sock.sendto(packet, (host, port))
    return {"host": host, "port": port, "sent_bytes": sent, "started_unix": started, "ended_unix": time.time()}


def print_table(profiles: Sequence[Profile]) -> None:
    for profile in profiles:
        print(
            f"{profile.profile_id:42s} {profile.suite:7s} {profile.category:20s} {profile.target:22s} "
            f"{profile.risk:9s} {','.join(profile.tags)}"
        )


def print_hexdump(packet: bytes) -> None:
    hexstr = binascii.hexlify(packet).decode("ascii")
    for offset in range(0, len(hexstr), 32):
        chunk = hexstr[offset : offset + 32]
        print(f"{offset // 2:04x}: {' '.join(chunk[i:i+2] for i in range(0, len(chunk), 2))}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build and send SP002 malformed TC UDP datagrams.")
    parser.add_argument("--target", help="filter by target, e.g. FM, DS, GENERIC_ADCS")
    parser.add_argument("--tag", action="append", default=[], help="filter by tag or category; may be repeated")
    parser.add_argument(
        "--mode",
        choices=("safe", "hazardous", "short-all", "all"),
        default=None,
        help="profile set: quick safe, quick hazardous, all quick, or complete matrix",
    )
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("list", help="list available profiles")

    build = sub.add_parser("build", help="build profiles without sending")
    build.add_argument("profiles", nargs="*", help="profile ids; omit for filtered set")
    build.add_argument("--dump-dir", type=Path, help="write .bin and .json files")
    build.add_argument("--json", action="store_true", help="print profile metadata JSON")
    build.add_argument("--hexdump", action="store_true", help="print packet hexdump")

    send = sub.add_parser("send", help="send profiles as raw UDP datagrams")
    send.add_argument("profiles", nargs="*", help="profile ids; omit for filtered set")
    send.add_argument("--host", default=DEFAULT_CI_HOST, help=f"CI host, default {DEFAULT_CI_HOST}")
    send.add_argument("--port", type=int, default=DEFAULT_CI_PORT, help=f"CI UDP port, default {DEFAULT_CI_PORT}")
    send.add_argument("--interval", type=float, default=0.2, help="seconds between packets")
    send.add_argument("--timeout", type=float, default=1.0, help="socket timeout")
    send.add_argument("--dump-dir", type=Path, help="write sent .bin and .json files")
    send.add_argument("--json", action="store_true", help="print send result JSON")
    send.add_argument("--dry-run", action="store_true", help="build and optionally dump, but do not send")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd is None:
        parser.error("a subcommand is required: list, build, or send")
    mode = args.mode or "safe"
    profiles = make_catalog()

    if args.cmd == "list":
        selected = select_profiles(profiles, (), args.target, args.tag, mode)
        print_table(selected)
        print(f"\nTotal: {len(selected)}")
        return 0

    selected = select_profiles(profiles, args.profiles, args.target, args.tag, mode)
    if not selected:
        print("No profiles selected", file=sys.stderr)
        return 2

    results: List[Dict[str, object]] = []
    for index, profile in enumerate(selected):
        pkt = profile.packet()
        meta = profile.to_json(pkt)
        if getattr(args, "dump_dir", None):
            meta.update(dump_profile(profile, args.dump_dir))

        if args.cmd == "build":
            if args.hexdump:
                print(f"== {profile.profile_id} ({len(pkt)} bytes) ==")
                print_hexdump(pkt)
            results.append(meta)
            continue

        if args.cmd == "send":
            if args.dry_run:
                send_meta = {"dry_run": True, "host": args.host, "port": args.port, "sent_bytes": 0}
            else:
                send_meta = send_packet(pkt, args.host, args.port, args.timeout)
            meta.update(send_meta)
            results.append(meta)
            if index + 1 < len(selected):
                time.sleep(args.interval)

    if getattr(args, "json", False):
        print(json.dumps(results if len(results) != 1 else results[0], indent=2, sort_keys=True))
    elif args.cmd == "build" and not getattr(args, "hexdump", False):
        for item in results:
            print(f"{item['profile_id']} len={item['packet_len']} checksum_result={item['checksum_result']}")
    elif args.cmd == "send":
        for item in results:
            mode = "DRY" if item.get("dry_run") else "SENT"
            print(f"{mode} {item['profile_id']} len={item['packet_len']} to {item['host']}:{item['port']}")

    return 0


if __name__ == "__main__":
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    raise SystemExit(main())
