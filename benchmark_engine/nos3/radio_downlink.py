from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any

from benchmark_engine.nos3.cosmos_driver import run_ruby_script


RADIO_DOWNLINK_SERVICE = "radio-sim"
RADIO_DOWNLINK_SERVICE_PORT = 5011
RADIO_INTERFACE = "RADIO"
RADIO_COSMOS_PORT = 6011


@dataclass
class RadioDownlinkSession:
    """Owns the runtime TO routing needed for RADIO downlink benchmark cases."""

    cosmos_container: str
    owner: str
    ready_timeout_seconds: float
    radio_service: str = RADIO_DOWNLINK_SERVICE
    radio_service_port: int = RADIO_DOWNLINK_SERVICE_PORT
    radio_interface: str = RADIO_INTERFACE
    radio_cosmos_port: int = RADIO_COSMOS_PORT
    enabled: bool = False
    ready: bool = False
    disabled: bool | None = None
    cleanup_warning: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    _closed: bool = False

    def open(self) -> bool:
        enable = _debug_command(
            self.cosmos_container,
            f"TO_ENABLE_OUTPUT with DEST_IP '{self.radio_service}', DEST_PORT {self.radio_service_port}",
        )
        self.enabled = bool(enable.get("ok"))
        self.events.append({"event": "radio_downlink_enabled", **enable})
        if not self.enabled:
            return False

        ready = _wait_for_radio_telemetry(
            self.cosmos_container,
            self.ready_timeout_seconds,
            self.radio_interface,
            self.radio_cosmos_port,
        )
        self.ready = bool(ready.get("ok"))
        self.events.append({"event": "radio_downlink_ready", **ready})
        return self.ready

    def close(self) -> dict[str, Any]:
        if self._closed:
            return self.snapshot()
        self._closed = True
        try:
            disable = _debug_command(self.cosmos_container, "TO_DISABLE_OUTPUT")
            self.disabled = bool(disable.get("ok"))
            if not self.disabled:
                self.cleanup_warning = str(disable.get("error") or "CFS TO_DISABLE_OUTPUT was not confirmed")
            self.events.append({"event": "radio_downlink_disabled", **disable})
        except Exception as error:  # Cleanup must never replace a case failure.
            self.disabled = False
            self.cleanup_warning = f"CFS TO_DISABLE_OUTPUT cleanup raised {error.__class__.__name__}: {error}"
            self.events.append(
                {
                    "event": "radio_downlink_disabled",
                    "ok": False,
                    "error": self.cleanup_warning,
                }
            )
        return self.snapshot()

    def snapshot(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "radio_downlink_enabled": self.enabled,
            "radio_downlink_ready": self.ready,
            "radio_downlink_disabled": self.disabled,
            "cleanup_warning": self.cleanup_warning,
            "radio_service": self.radio_service,
            "radio_service_port": self.radio_service_port,
            "radio_interface": self.radio_interface,
            "radio_cosmos_port": self.radio_cosmos_port,
            "events": self.events,
        }


def _debug_command(container: str, command: str) -> dict[str, Any]:
    command_literal = json.dumps(command)
    ruby = f"""
require 'json'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

begin
  command = {command_literal}
  cmd("CFS #{{command}}")
  sleep 0.25
  puts JSON.generate({{ok: true, target: 'CFS', command: command}})
rescue Exception => error
  puts JSON.generate({{
    ok: false,
    target: 'CFS',
    command: command,
    error_class: error.class.to_s,
    error: error.message,
    backtrace: error.backtrace ? error.backtrace.first(8) : []
  }})
  exit 3
end
"""
    return run_ruby_script(container=container, ruby=ruby)


def _wait_for_radio_telemetry(
    container: str,
    timeout_seconds: float,
    radio_interface: str,
    radio_cosmos_port: int,
) -> dict[str, Any]:
    return send_radio_housekeeping(
        container=container,
        timeout_seconds=timeout_seconds,
        radio_interface=radio_interface,
        radio_cosmos_port=radio_cosmos_port,
    )


def send_radio_housekeeping(
    *,
    container: str,
    timeout_seconds: float,
    radio_interface: str = RADIO_INTERFACE,
    radio_cosmos_port: int = RADIO_COSMOS_PORT,
) -> dict[str, Any]:
    """Issue the DEBUG SC housekeeping request and prove its RADIO receipt."""
    timeout_literal = json.dumps(timeout_seconds)
    ruby = f"""
require 'json'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

begin
  cmd('CFS SC_SEND_HK')
  wait_check_packet('CFS_RADIO', 'SC_HKTLM', 1, {timeout_literal})
  puts JSON.generate({{
    ok: true,
    control_target: 'CFS',
    control_command: 'SC_SEND_HK',
    radio_target: 'CFS_RADIO',
    radio_packet: 'SC_HKTLM',
    radio_interface: {json.dumps(radio_interface)},
    radio_cosmos_port: {radio_cosmos_port}
  }})
rescue Exception => error
  puts JSON.generate({{
    ok: false,
    control_target: 'CFS',
    control_command: 'SC_SEND_HK',
    radio_target: 'CFS_RADIO',
    radio_packet: 'SC_HKTLM',
    error_class: error.class.to_s,
    error: error.message,
    backtrace: error.backtrace ? error.backtrace.first(8) : []
  }})
  exit 3
end
"""
    return run_ruby_script(container=container, ruby=ruby)
