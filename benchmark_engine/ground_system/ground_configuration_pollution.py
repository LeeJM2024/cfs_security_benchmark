from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
from typing import Any

from benchmark_engine.nos3.cosmos_driver import run_ruby_script
from benchmark_engine.ground_system.command_dictionary_pollution import RunConfig, _read_container_text, _restart_cmd_tlm_server, _write_container_text
from benchmark_engine.ground_system.command_audit_attribution import _read_last_command_buffer, _send_command, _snapshot, _values_equal
from benchmark_engine.core.scenario import load_scenario


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCENARIO = ROOT / "security_suites" / "ground_system" / "scenarios" / "ground_configuration_pollution.yaml"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run live GS-004 ground configuration pollution benchmark")
    parser.add_argument("--scenario", type=Path, default=DEFAULT_SCENARIO)
    parser.add_argument("--case", action="append", dest="case_ids")
    parser.add_argument("--container")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--acknowledge-live-configuration-pollution", action="store_true")
    args = parser.parse_args()
    scenario = load_scenario(args.scenario)
    if scenario.id.upper() != "GS-004":
        raise SystemExit(f"Expected GS-004 scenario, got {scenario.id}")
    attack = scenario.attack
    config = RunConfig(
        container=args.container or str(attack["docker_container"]),
        output_dir=args.output_dir or _output_dir(scenario.id),
        command_server_root=str(attack["command_server_root"]),
        timeout_seconds=10.0,
        server_timeout_seconds=60.0,
        poll_interval=0.5,
        settle_seconds=0.5,
    )
    cases = [dict(item) for item in attack["cases"]]
    if args.case_ids:
        by_id = {str(item["id"]): item for item in cases}
        cases = [by_id[item] for item in args.case_ids]
    if args.dry_run:
        for case in cases:
            print(f"{case['id']}: {case['config_path']} :: {case['mutation']['original']!r} -> {case['mutation']['replacement']!r}")
        return
    if not args.acknowledge_live_configuration_pollution:
        raise SystemExit("Refusing live configuration pollution without --acknowledge-live-configuration-pollution")
    config.output_dir.mkdir(parents=True, exist_ok=True)
    results = [_run_case(case, config) for case in cases]
    score = {"scenario_id": scenario.id, "passed": all(item["passed"] for item in results), "cases": results}
    _write_json(config.output_dir / "score.json", score)
    print(json.dumps(score, indent=2))


def _run_case(case: dict[str, Any], config: RunConfig) -> dict[str, Any]:
    case_dir = config.output_dir / str(case["id"])
    case_dir.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, Any] = {"case_id": case["id"], "started_at": _now()}
    original = ""
    changed = False
    result = False
    reason = "case did not complete"
    try:
        source = _read_container_text(config.container, str(case["config_path"]))
        if not source.get("ok"):
            raise RuntimeError("configuration backup failed")
        original = str(source["text"])
        evidence["backup_sha256"] = _hash(original)
        (case_dir / Path(str(case["config_path"])).name).write_text(original, encoding="utf-8")
        mutation = dict(case["mutation"])
        if original.count(str(mutation["original"])) != 1:
            raise RuntimeError("configuration mutation did not match exactly once")
        polluted = original.replace(str(mutation["original"]), str(mutation["replacement"]), 1)
        write = _write_container_text(config.container, str(case["config_path"]), polluted)
        if not write.get("ok"):
            raise RuntimeError("configuration write failed")
        changed = True
        if case["kind"] == "route" and not _restart_cmd_tlm_server(config).get("ok"):
            raise RuntimeError("CmdTlmServer did not reload polluted routing configuration")
        if case["kind"] == "procedure":
            sent = _run_procedure(config.container, str(case["procedure_path"]))
        else:
            before = _snapshot(case, config)
            evidence["before"] = before
            sent = _send_command(config.container, str(case["command"]))
        evidence["operation"] = sent
        time.sleep(config.settle_seconds)
        if case["kind"] == "procedure":
            buffer = _read_last_command_buffer(config.container, str(case["command"]))
            evidence["command_buffer"] = buffer
            result = bool(buffer.get("ok")) and str(case["expected_packet_hex_fragment"]).lower() in str(buffer.get("packet_hex", "")).lower()
            reason = "normal procedure emitted polluted command parameters" if result else "procedure did not expose expected polluted command buffer"
        else:
            after = _snapshot(case, config)
            evidence["after"] = after
            result = _same_counter(before, after)
            reason = "polluted route prevented the safe command from reaching cFS" if result else "route misdirection evidence failed"
    except Exception as error:
        reason = f"{type(error).__name__}: {error}"
    finally:
        if changed:
            restored = _write_container_text(config.container, str(case["config_path"]), original)
            evidence["restore_write"] = restored
            if case["kind"] == "route":
                evidence["restart_after_restore"] = _restart_cmd_tlm_server(config)
            verify = _read_container_text(config.container, str(case["config_path"]))
            evidence["restore_matches_backup"] = bool(verify.get("ok")) and _hash(str(verify.get("text", ""))) == _hash(original)
            if case["kind"] == "procedure" and evidence["restore_matches_backup"]:
                evidence["normal_recovery"] = _run_procedure(config.container, str(case["procedure_path"]))
            if case["kind"] == "route" and evidence["restore_matches_backup"]:
                recovery_before = _snapshot(case, config)
                evidence["normal_recovery"] = _send_command(config.container, str(case["command"]))
                evidence["recovery_after"] = _snapshot(case, config)
                evidence["route_recovered"] = not _same_counter(recovery_before, evidence["recovery_after"])
        evidence["finished_at"] = _now()
        _write_json(case_dir / "evidence.json", evidence)
    restored = bool(evidence.get("restore_matches_backup"))
    recovered = bool(evidence.get("route_recovered", evidence.get("normal_recovery", {}).get("ok", False)))
    return {"case_id": case["id"], "passed": result and restored and recovered, "reason": reason, "configuration_restored": restored, "normal_recovery_ok": recovered}


def _run_procedure(container: str, path: str) -> dict[str, Any]:
    ruby = f"""
require 'json'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script
$LOAD_PATH.unshift('/home/leejm/nos3/gsw/cosmos/config/targets/CFS/lib')
begin
  load {json.dumps(path)}
  puts JSON.generate({{ok: true, procedure: {json.dumps(path)}}})
rescue Exception => error
  puts JSON.generate({{ok: false, error_class: error.class.to_s, error: error.message}})
  exit 3
end
"""
    return run_ruby_script(container=container, ruby=ruby)


def _same_counter(before: dict[str, Any], after: dict[str, Any]) -> bool:
    return _values_equal(dict(before.get("values", {})).get("cmd_count"), dict(after.get("values", {})).get("cmd_count"))


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _output_dir(scenario_id: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return ROOT / "artifacts" / "runs" / f"{stamp}_{scenario_id.lower().replace('-', '')}_ground_configuration_pollution"


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    main()
