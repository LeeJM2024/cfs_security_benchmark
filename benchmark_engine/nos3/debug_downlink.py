from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any

from benchmark_engine.nos3.cosmos_driver import run_ruby_script


DEBUG_INTERFACE = "DEBUG"
DEBUG_COSMOS_PORT = 5013
DEBUG_SOURCE_APP = "TO_LAB"


@dataclass
class DebugDownlinkSession:
    """Records readiness for the default cFS TO DEBUG downlink path."""

    cosmos_container: str
    owner: str
    ready_timeout_seconds: float
    debug_interface: str = DEBUG_INTERFACE
    debug_cosmos_port: int = DEBUG_COSMOS_PORT
    debug_source_app: str = DEBUG_SOURCE_APP
    ready: bool = False
    cleanup_warning: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    _closed: bool = False

    def open(self) -> bool:
        result = send_debug_housekeeping(
            container=self.cosmos_container,
            timeout_seconds=self.ready_timeout_seconds,
            debug_interface=self.debug_interface,
            debug_cosmos_port=self.debug_cosmos_port,
        )
        self.ready = bool(result.get("ok"))
        self.events.append({"event": "debug_downlink_ready", **result})
        return self.ready

    def close(self) -> dict[str, Any]:
        if not self._closed:
            self._closed = True
            self.events.append(
                {
                    "event": "debug_downlink_closed",
                    "ok": True,
                    "reason": "default DEBUG downlink is not reconfigured by the benchmark",
                }
            )
        return self.snapshot()

    def snapshot(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "debug_downlink_default": True,
            "debug_downlink_ready": self.ready,
            "debug_intercept_method": "TPROXY",
            "cleanup_warning": self.cleanup_warning,
            "debug_interface": self.debug_interface,
            "debug_cosmos_port": self.debug_cosmos_port,
            "debug_source_app": self.debug_source_app,
            "events": self.events,
        }


def send_debug_housekeeping(
    *,
    container: str,
    timeout_seconds: float,
    debug_interface: str = DEBUG_INTERFACE,
    debug_cosmos_port: int = DEBUG_COSMOS_PORT,
) -> dict[str, Any]:
    """Issue a normal DEBUG command and require its DEBUG housekeeping return."""
    timeout_literal = json.dumps(timeout_seconds)
    ruby = f"""
require 'json'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

begin
  cmd('CFS SC_SEND_HK')
  wait_check_packet('CFS', 'SC_HKTLM', 1, {timeout_literal})
  puts JSON.generate({{
    ok: true,
    control_target: 'CFS',
    control_command: 'SC_SEND_HK',
    debug_target: 'CFS',
    debug_packet: 'SC_HKTLM',
    debug_interface: {json.dumps(debug_interface)},
    debug_cosmos_port: {debug_cosmos_port}
  }})
rescue Exception => error
  puts JSON.generate({{
    ok: false,
    control_target: 'CFS',
    control_command: 'SC_SEND_HK',
    debug_target: 'CFS',
    debug_packet: 'SC_HKTLM',
    error_class: error.class.to_s,
    error: error.message,
    backtrace: error.backtrace ? error.backtrace.first(8) : []
  }})
  exit 3
end
"""
    return run_ruby_script(container=container, ruby=ruby)
