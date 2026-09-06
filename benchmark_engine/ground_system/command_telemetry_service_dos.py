from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import time
from typing import Any

from benchmark_engine.nos3.cosmos_driver import ensure_cmd_tlm_server, run_ruby_script
from benchmark_engine.core.scenario import load_scenario


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCENARIO = ROOT / "security_suites" / "ground_system" / "scenarios" / "command_telemetry_service_dos.yaml"


@dataclass(frozen=True)
class Config:
    container: str
    output_dir: Path
    duration: float
    max_operations: int
    workers: int
    canary_interval: float
    canary_timeout: float
    failure_threshold: int


def main() -> None:
    parser = argparse.ArgumentParser(description="Run bounded GS-005 ground command/telemetry service DoS benchmark")
    parser.add_argument("--scenario", type=Path, default=DEFAULT_SCENARIO)
    parser.add_argument("--case", action="append", dest="case_ids")
    parser.add_argument("--container")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--duration", type=float, default=8.0, help="Maximum load duration per case in seconds")
    parser.add_argument("--max-operations", type=int, default=80, help="Hard maximum load operations per case")
    parser.add_argument("--workers", type=int, default=4, help="Maximum concurrent load workers")
    parser.add_argument("--canary-interval", type=float, default=0.75)
    parser.add_argument("--canary-timeout", type=float, default=4.0)
    parser.add_argument("--failure-threshold", type=int, default=2)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--acknowledge-bounded-service-load", action="store_true")
    args = parser.parse_args()
    if args.duration <= 0 or args.duration > 30 or args.max_operations <= 0 or args.max_operations > 500 or args.workers <= 0 or args.workers > 16:
        raise SystemExit("bounds: duration 0-30, max-operations 1-500, workers 1-16")
    scenario = load_scenario(args.scenario)
    if scenario.id.upper() != "GS-005":
        raise SystemExit(f"Expected GS-005 scenario, got {scenario.id}")
    attack = scenario.attack
    config = Config(args.container or str(attack["docker_container"]), args.output_dir or _output_dir(), args.duration, args.max_operations, args.workers, args.canary_interval, args.canary_timeout, args.failure_threshold)
    cases = [dict(item) for item in attack["cases"]]
    if args.case_ids:
        by_id = {str(item["id"]): item for item in cases}
        cases = [by_id[item] for item in args.case_ids]
    if args.dry_run:
        print(f"GS-005 bounded dry run: duration={config.duration}s operations<={config.max_operations} workers={config.workers}")
        for case in cases:
            print(f"{case['id']}: {case['load_kind']}")
        return
    if not args.acknowledge_bounded_service_load:
        raise SystemExit("Refusing bounded live load without --acknowledge-bounded-service-load")
    server = ensure_cmd_tlm_server(container=config.container, timeout_seconds=30.0)
    if not server.get("ok"):
        raise SystemExit(f"CmdTlmServer unavailable: {server.get('error')}")
    config.output_dir.mkdir(parents=True, exist_ok=True)
    results = [_run_case(case, dict(attack), config) for case in cases]
    score = {"scenario_id": scenario.id, "benchmark_execution_passed": all(item["benchmark_execution_passed"] for item in results), "security_verdict": "VULNERABLE" if any(item["service_degradation_observed"] for item in results) else "NOT_DEMONSTRATED", "cases": results}
    _write_json(config.output_dir / "score.json", score)
    print(json.dumps(score, indent=2))


def _run_case(case: dict[str, Any], attack: dict[str, Any], config: Config) -> dict[str, Any]:
    case_dir = config.output_dir / str(case["id"])
    case_dir.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, Any] = {"case_id": case["id"], "started_at": _now(), "bounds": _bounds(config)}
    baseline = _canaries(attack, config)
    evidence["baseline"] = baseline
    process = subprocess.Popen(["docker", "exec", config.container, "/usr/bin/ruby", "-e", _load_ruby(case, config)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    samples: list[dict[str, Any]] = []
    consecutive_failures = 0
    while process.poll() is None:
        sample = _canaries(attack, config)
        samples.append(sample)
        if not sample["telemetry"]["ok"] or not sample["command"]["ok"]:
            consecutive_failures += 1
        else:
            consecutive_failures = 0
        if consecutive_failures >= config.failure_threshold:
            evidence["degradation_threshold_reached"] = True
        time.sleep(config.canary_interval)
    stdout, stderr = process.communicate(timeout=5)
    load = _last_json(stdout) or {"ok": False, "stdout": stdout, "stderr": stderr, "returncode": process.returncode}
    evidence["load"] = load
    evidence["canary_samples"] = samples
    recovery_started = time.monotonic()
    recovery = _wait_for_healthy(attack, config)
    evidence["recovery"] = recovery
    evidence["recovery_time_seconds"] = time.monotonic() - recovery_started
    evidence["finished_at"] = _now()
    _write_json(case_dir / "evidence.json", evidence)
    degraded = bool(evidence.get("degradation_threshold_reached"))
    return {"case_id": case["id"], "benchmark_execution_passed": bool(load.get("ok")) and recovery["ok"], "service_degradation_observed": degraded, "telemetry_canary_available_during_load": all(sample["telemetry"]["ok"] for sample in samples), "command_canary_available_during_load": all(sample["command"]["ok"] for sample in samples), "rate_limit_observed": _rate_limited(load), "priority_recovery_channel_observed": False, "recovery_time_seconds": evidence["recovery_time_seconds"]}


def _canaries(attack: dict[str, Any], config: Config) -> dict[str, Any]:
    telemetry = dict(attack["telemetry_canary"])
    command = dict(attack["command_canary"])
    return {"telemetry": _telemetry_canary(config.container, str(telemetry["request"]), str(telemetry["value"]), config.canary_timeout), "command": _command_canary(config.container, str(command["command"]), str(command["counter_request"]), str(command["counter"]), config.canary_timeout), "at": _now()}


def _telemetry_canary(container: str, request: str, value: str, timeout: float) -> dict[str, Any]:
    return _ruby_timed(container, f"cmd({json.dumps(request)}); tlm({json.dumps(value)})", timeout)


def _command_canary(container: str, command: str, request: str, counter: str, timeout: float) -> dict[str, Any]:
    ruby = f"""
before = tlm({json.dumps(counter)})
cmd({json.dumps(command)})
after = before
deadline = Time.now + {json.dumps(timeout)}
while Time.now < deadline && after == before
  cmd({json.dumps(request)})
  sleep(0.35)
  after = tlm({json.dumps(counter)})
end
raise 'counter did not increment' unless after != before
"""
    return _ruby_timed(container, ruby, timeout)


def _ruby_timed(container: str, body: str, timeout: float) -> dict[str, Any]:
    ruby = f"""
require 'json'; require 'cosmos'; require 'cosmos/script'; include Cosmos::Script
started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
begin
  {body}
  puts JSON.generate({{ok: true, latency_ms: (Process.clock_gettime(Process::CLOCK_MONOTONIC)-started)*1000}})
rescue Exception => error
  puts JSON.generate({{ok: false, error: error.message, latency_ms: (Process.clock_gettime(Process::CLOCK_MONOTONIC)-started)*1000}})
  exit 3
end
"""
    payload = run_ruby_script(container=container, ruby=ruby)
    latency_ms = payload.get("latency_ms")
    payload["timeout_exceeded"] = latency_ms is None or float(latency_ms) > timeout * 1000
    payload["ok"] = bool(payload.get("ok")) and not payload["timeout_exceeded"]
    return payload


def _load_ruby(case: dict[str, Any], config: Config) -> str:
    operation = f"tlm({json.dumps(str(case['load_telemetry']))})" if case["load_kind"] == "telemetry_read" else f"cmd({json.dumps(str(case['load_command']))})"
    return f"""
require 'json'; require 'cosmos'; require 'cosmos/script'; include Cosmos::Script
deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + {config.duration}
max_operations = {config.max_operations}; count = 0; ok = 0; errors = []; mutex = Mutex.new
workers = Array.new({config.workers}) do
  Thread.new do
    loop do
      allowed = mutex.synchronize {{ if count >= max_operations || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline then false else count += 1; true end }}
      break unless allowed
      begin; {operation}; mutex.synchronize {{ ok += 1 }}; rescue Exception => error; mutex.synchronize {{ errors << error.class.to_s + ': ' + error.message }}; end
    end
  end
end
workers.each(&:join)
puts JSON.generate({{ok: true, attempts: count, successes: ok, failures: errors.length, errors: errors.first(20)}})
"""


def _wait_for_healthy(attack: dict[str, Any], config: Config) -> dict[str, Any]:
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        sample = _canaries(attack, config)
        if sample["telemetry"]["ok"] and sample["command"]["ok"]:
            return {"ok": True, "sample": sample}
        time.sleep(config.canary_interval)
    return {"ok": False}


def _rate_limited(load: dict[str, Any]) -> bool:
    return any("rate" in str(error).lower() or "thrott" in str(error).lower() for error in load.get("errors", []))


def _last_json(output: str) -> dict[str, Any] | None:
    for line in reversed(output.splitlines()):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            pass
    return None


def _bounds(config: Config) -> dict[str, Any]:
    return {"duration_seconds": config.duration, "max_operations": config.max_operations, "workers": config.workers}


def _output_dir() -> Path:
    return ROOT / "artifacts" / "runs" / f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_gs005_command_telemetry_service_dos"


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    main()
