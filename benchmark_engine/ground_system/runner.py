from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmark_engine.core.scenario import Scenario, load_scenario, load_scenarios


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(description="Preview Ground system benchmark scenarios")
    parser.add_argument("--scenario", help="Scenario ID such as GS-001, or path to one scenario YAML/JSON")
    parser.add_argument("--all", action="store_true", help="Preview all Ground system scenarios")
    parser.add_argument("--json", action="store_true", help="Print selected scenarios as JSON")
    args = parser.parse_args()

    scenarios = _select_scenarios(args.scenario, args.all)
    if not scenarios:
        raise SystemExit("No Ground system scenarios selected. Use --all or --scenario GS-001.")

    if args.json:
        print(json.dumps([_scenario_to_dict(scenario) for scenario in scenarios], ensure_ascii=False, indent=2))
        return

    print(f"Loaded {len(scenarios)} Ground system scenario(s)")
    for scenario in scenarios:
        print(f"\nscenario: {scenario.id} {scenario.name}")
        print(f"attack.type: {scenario.attack_type}")
        print(f"injection: {scenario.description['injection_method']}")
    print("\nRun GS-001 live with:")
    print("python3 -m benchmark_engine.ground_system.live_runner")


def _select_scenarios(value: str | None, run_all: bool) -> list[Scenario]:
    scenario_dir = PROJECT_ROOT / "security_suites" / "ground_system" / "scenarios"
    scenarios = load_scenarios(scenario_dir)
    if run_all:
        return scenarios
    if not value:
        return []

    candidate = Path(value)
    if candidate.exists():
        return [load_scenario(candidate)]

    by_id = {scenario.id.upper(): scenario for scenario in scenarios}
    selected = by_id.get(value.upper())
    if selected is None:
        known = ", ".join(sorted(by_id))
        raise SystemExit(f"Unknown scenario {value!r}. Known Ground system scenarios: {known}")
    return [selected]


def _scenario_to_dict(scenario: Scenario) -> dict[str, object]:
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
