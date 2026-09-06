from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmark_engine.core.scenario import REQUIRED_DESCRIPTION_FIELDS, Scenario


def scenario_to_dict(scenario: Scenario) -> dict[str, Any]:
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


def write_scenario_index(path: Path, scenarios: list[Scenario], *, title: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "summary.json").write_text(
        json.dumps(
            {
                "title": title,
                "scenario_count": len(scenarios),
                "scenarios": [scenario_to_dict(scenario) for scenario in scenarios],
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (path / "summary.md").write_text(_scenario_index_markdown(scenarios, title=title), encoding="utf-8")


def _scenario_index_markdown(scenarios: list[Scenario], *, title: str) -> str:
    passed_schema = sum(1 for scenario in scenarios if _scenario_schema_complete(scenario))
    lines = [
        f"# {title}",
        "",
        "## Scope",
        "",
        f"- Scenario count: `{len(scenarios)}`",
        f"- Complete description schema: `{passed_schema}/{len(scenarios)}`",
        "- Mode: `dry-run / scenario index`",
        "",
        "## Scenario Matrix",
        "",
        "| Scenario | Entry | Component | CPS Type | Injection | Metrics |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for scenario in scenarios:
        description = scenario.description
        lines.append(
            "| "
            f"`{scenario.id}` {scenario.name} | "
            f"{_cell(description.get('attack_entry'))} | "
            f"{_cell(description.get('affected_component'))} | "
            f"{_cell(description.get('cps_type'))} | "
            f"{_cell(description.get('injection_method'))} | "
            f"{_cell(', '.join(scenario.metrics))} |"
        )

    lines.extend(["", "## Required Description Chain", ""])
    lines.append("`" + " -> ".join(REQUIRED_DESCRIPTION_FIELDS) + "`")
    lines.append("")
    return "\n".join(lines)


def _scenario_schema_complete(scenario: Scenario) -> bool:
    return all(bool(scenario.description.get(field)) for field in REQUIRED_DESCRIPTION_FIELDS)


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")
