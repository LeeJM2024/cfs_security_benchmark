from __future__ import annotations

import argparse
import json
from pathlib import Path

from cfs_security_benchmark.scenario import load_scenarios


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run cFS/NOS3 security benchmark scenarios")
    parser.add_argument("--domain", default="rf_link", help="Scenario domain directory under scenarios/")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print scenarios without sending packets")
    parser.add_argument("--json", action="store_true", help="Print scenario metadata as JSON")
    args = parser.parse_args()

    scenario_dir = PROJECT_ROOT / "scenarios" / args.domain
    scenarios = load_scenarios(scenario_dir)

    if args.json:
        print(json.dumps([_scenario_to_dict(scenario) for scenario in scenarios], ensure_ascii=False, indent=2))
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

    if args.dry_run:
        print("\nDry run complete. No packets were sent.")
        return

    print("\nUse cfs_security_benchmark.attacks.rf_link_proxy with a selected scenario to inject traffic effects.")


def _scenario_to_dict(scenario) -> dict:
    return {
        "id": scenario.id,
        "name": scenario.name,
        "domain": scenario.domain,
        "description": scenario.description,
        "attack": scenario.attack,
        "metrics": scenario.metrics,
        "pass_criteria": scenario.pass_criteria,
        "notes": scenario.notes,
    }


if __name__ == "__main__":
    main()
