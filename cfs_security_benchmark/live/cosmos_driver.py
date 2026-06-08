from __future__ import annotations

from dataclasses import dataclass
import json
import subprocess
from typing import Any


@dataclass(frozen=True)
class CosmosCommandResult:
    ok: bool
    target: str
    command: str
    counter_before: int | float | None
    counter_after: int | float | None
    raw: dict[str, Any]

    @property
    def counter_delta(self) -> int | float | None:
        if self.counter_before is None or self.counter_after is None:
            return None
        return self.counter_after - self.counter_before


def send_noop_and_read_counter(
    *,
    container: str,
    target: str,
    command: str,
    housekeeping_packet: str,
    counter_item: str,
    wait_seconds: float,
    housekeeping_command: str | None = None,
    telemetry_timeout: float = 10.0,
) -> CosmosCommandResult:
    ruby = _ruby_script(
        target=target,
        command=command,
        housekeeping_packet=housekeeping_packet,
        counter_item=counter_item,
        wait_seconds=wait_seconds,
        housekeeping_command=housekeeping_command,
        telemetry_timeout=telemetry_timeout,
    )
    result = subprocess.run(
        ["docker", "exec", container, "/usr/bin/ruby", "-e", ruby],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    payload = _last_json_line(result.stdout)
    if payload is None:
        payload = {
            "ok": False,
            "error": "COSMOS command driver did not emit JSON",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    elif result.returncode != 0:
        payload.setdefault("ok", False)
        payload.setdefault("stderr", result.stderr)
        payload.setdefault("returncode", result.returncode)

    return CosmosCommandResult(
        ok=bool(payload.get("ok")),
        target=target,
        command=command,
        counter_before=payload.get("before"),
        counter_after=payload.get("after"),
        raw=payload,
    )


def send_noop_burst_and_read_counter(
    *,
    container: str,
    target: str,
    command: str,
    housekeeping_packet: str,
    counter_item: str,
    count: int,
    spacing_seconds: float,
    settle_seconds: float,
) -> CosmosCommandResult:
    ruby = _burst_ruby_script(
        target=target,
        command=command,
        housekeeping_packet=housekeeping_packet,
        counter_item=counter_item,
        count=count,
        spacing_seconds=spacing_seconds,
        settle_seconds=settle_seconds,
    )
    result = subprocess.run(
        ["docker", "exec", container, "/usr/bin/ruby", "-e", ruby],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    payload = _last_json_line(result.stdout)
    if payload is None:
        payload = {
            "ok": False,
            "error": "COSMOS burst command driver did not emit JSON",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    elif result.returncode != 0:
        payload.setdefault("ok", False)
        payload.setdefault("stderr", result.stderr)
        payload.setdefault("returncode", result.returncode)

    return CosmosCommandResult(
        ok=bool(payload.get("ok")),
        target=target,
        command=command,
        counter_before=payload.get("before"),
        counter_after=payload.get("after"),
        raw=payload,
    )


def reconnect_interface(*, container: str, interface: str, settle_seconds: float = 1.0) -> dict[str, Any]:
    ruby = f"""
require 'json'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

interface = {json.dumps(interface)}
settle_seconds = {json.dumps(settle_seconds)}

begin
  before = interface_state(interface) rescue nil
  disconnect_interface(interface)
  sleep(settle_seconds)
  connect_interface(interface)
  sleep(settle_seconds)
  after = interface_state(interface) rescue nil
  puts JSON.generate({{ok: true, interface: interface, before: before, after: after}})
rescue Exception => error
  puts JSON.generate({{
    ok: false,
    interface: interface,
    error_class: error.class.to_s,
    error: error.message,
    backtrace: error.backtrace ? error.backtrace.first(8) : []
  }})
  exit 4
end
"""
    result = subprocess.run(
        ["docker", "exec", container, "/usr/bin/ruby", "-e", ruby],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    payload = _last_json_line(result.stdout)
    if payload is None:
        return {
            "ok": False,
            "interface": interface,
            "error": "COSMOS interface reconnect did not emit JSON",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    if result.returncode != 0:
        payload.setdefault("ok", False)
        payload.setdefault("stderr", result.stderr)
        payload.setdefault("returncode", result.returncode)
    return payload


def _ruby_script(
    *,
    target: str,
    command: str,
    housekeeping_packet: str,
    counter_item: str,
    wait_seconds: float,
    housekeeping_command: str | None,
    telemetry_timeout: float,
) -> str:
    target_literal = json.dumps(target)
    command_literal = json.dumps(command)
    packet_literal = json.dumps(housekeeping_packet)
    counter_literal = json.dumps(counter_item)
    wait_literal = json.dumps(wait_seconds)
    telemetry_timeout_literal = json.dumps(telemetry_timeout)
    housekeeping_command_literal = json.dumps(housekeeping_command) if housekeeping_command else "nil"
    return f"""
require 'json'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

target = {target_literal}
command = {command_literal}
packet = {packet_literal}
counter = {counter_literal}
wait_seconds = {wait_literal}
telemetry_timeout = {telemetry_timeout_literal}
housekeeping_command = {housekeeping_command_literal}
counter_path = "#{{target}} #{{packet}} #{{counter}}"
command_path = "#{{target}} #{{command}}"
housekeeping_command_path = housekeeping_command ? "#{{target}} #{{housekeeping_command}}" : nil

begin
  cmd(housekeeping_command_path) if housekeeping_command_path
  sleep(wait_seconds)
  before = tlm(counter_path)
  cmd(command_path)
  deadline = Time.now + telemetry_timeout
  after = tlm(counter_path)
  while Time.now < deadline && after == before
    sleep(wait_seconds)
    after = tlm(counter_path)
  end
  cmd(housekeeping_command_path) if housekeeping_command_path
  sleep(wait_seconds) if housekeeping_command_path
  after = tlm(counter_path) if housekeeping_command_path
  puts JSON.generate({{ok: true, target: target, command: command, before: before, after: after}})
rescue Exception => error
  puts JSON.generate({{
    ok: false,
    target: target,
    command: command,
    before: defined?(before) ? before : nil,
    after: defined?(after) ? after : nil,
    error_class: error.class.to_s,
    error: error.message,
    backtrace: error.backtrace ? error.backtrace.first(8) : []
  }})
  exit 3
end
"""


def _burst_ruby_script(
    *,
    target: str,
    command: str,
    housekeeping_packet: str,
    counter_item: str,
    count: int,
    spacing_seconds: float,
    settle_seconds: float,
) -> str:
    target_literal = json.dumps(target)
    command_literal = json.dumps(command)
    packet_literal = json.dumps(housekeeping_packet)
    counter_literal = json.dumps(counter_item)
    count_literal = json.dumps(count)
    spacing_literal = json.dumps(spacing_seconds)
    settle_literal = json.dumps(settle_seconds)
    return f"""
require 'json'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

target = {target_literal}
command = {command_literal}
packet = {packet_literal}
counter = {counter_literal}
count = {count_literal}
spacing_seconds = {spacing_literal}
settle_seconds = {settle_literal}
counter_path = "#{{target}} #{{packet}} #{{counter}}"
command_path = "#{{target}} #{{command}}"

begin
  before = tlm(counter_path)
  sent = 0
  count.times do
    cmd(command_path)
    sent += 1
    sleep(spacing_seconds) if spacing_seconds > 0
  end
  sleep(settle_seconds) if settle_seconds > 0
  after = tlm(counter_path)
  puts JSON.generate({{ok: true, target: target, command: command, before: before, after: after, sent: sent}})
rescue Exception => error
  puts JSON.generate({{
    ok: false,
    target: target,
    command: command,
    before: defined?(before) ? before : nil,
    after: defined?(after) ? after : nil,
    sent: defined?(sent) ? sent : 0,
    error_class: error.class.to_s,
    error: error.message,
    backtrace: error.backtrace ? error.backtrace.first(8) : []
  }})
  exit 3
end
"""


def _last_json_line(output: str) -> dict[str, Any] | None:
    for line in reversed(output.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return None
