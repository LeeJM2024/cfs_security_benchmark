from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmark_engine.core.reporting import scenario_to_dict, write_scenario_index
from benchmark_engine.core.scenario import load_scenarios


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run cFS/NOS3 security benchmark scenarios")
    parser.add_argument("--domain", choices=("rf_link", "ground_system"), default="rf_link", help="Security-suite scenario domain to load")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print scenarios without sending packets")
    parser.add_argument("--json", action="store_true", help="Print scenario metadata as JSON")
    parser.add_argument(
        "--report-dir",
        type=Path,
        help="Write dry-run benchmark index artifacts to this directory",
    )
    args = parser.parse_args()

    scenario_dir = PROJECT_ROOT / "security_suites" / args.domain / "scenarios"
    scenarios = load_scenarios(scenario_dir)

    if args.json:
        print(json.dumps([scenario_to_dict(scenario) for scenario in scenarios], ensure_ascii=False, indent=2))
        return

    print(f"Loaded {len(scenarios)} scenario(s) from {scenario_dir}")
    for scenario in scenarios:
        print(f"\n[{scenario.id}] {scenario.name}")
        print(f"  attack_entry: {scenario.description['attack_entry']}")
        print(f"  affected_component: {scenario.description['affected_component']}")
        print(f"  cps_type: {scenario.description['cps_type']}")
        print(f"  security_consequence: {scenario.description['security_consequence']}")
        print(f"  recovery_strategy: {scenario.description['recovery_strategy']}")
        print(f"  injection_method: {scenario.description['injection_method']}")
        print(f"  attack.type: {scenario.attack_type}")

    if args.report_dir:
        write_scenario_index(
            args.report_dir,
            scenarios,
            title=f"cFS/NOS3 {args.domain} Security Benchmark Scenario Index",
        )
        print(f"\nScenario index written to {args.report_dir}")

    if args.dry_run:
        print("\nDry run complete. No packets were sent.")
        return

    print("\nUse benchmark_engine.rf_link.proxy with a selected scenario to inject traffic effects.")


if __name__ == "__main__":
    main()
