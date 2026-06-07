from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from cfs_security_benchmark.scenario import Scenario


@dataclass(frozen=True)
class Score:
    scenario_id: str
    passed: bool
    impact_score: int
    detection_score: int
    recovery_score: int
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "passed": self.passed,
            "impact_score": self.impact_score,
            "detection_score": self.detection_score,
            "recovery_score": self.recovery_score,
            "summary": self.summary,
        }


def score_proxy_log(scenario: Scenario, log_path: Path) -> Score:
    events = _read_events(log_path)
    counts: dict[str, int] = {}
    for event in events:
        name = str(event.get("event", "unknown"))
        counts[name] = counts.get(name, 0) + 1

    received = counts.get("packet_received", 0)
    forwarded = counts.get("packet_forwarded", 0)
    injected = sum(
        counts.get(name, 0)
        for name in ("packet_flooded", "packet_fabricated", "packet_replayed", "packet_bit_flipped")
    )

    pass_criteria = scenario.pass_criteria
    min_received = int(pass_criteria.get("min_packets_received", 0))
    min_attack_events = int(pass_criteria.get("min_attack_events", 0))
    max_forwarded = pass_criteria.get("max_packets_forwarded")

    passed = received >= min_received and injected >= min_attack_events
    if max_forwarded is not None:
        passed = passed and forwarded <= int(max_forwarded)

    impact_score = min(5, max(0, injected + max(0, received - forwarded)))
    detection_score = 1 if counts else 0
    recovery_score = 1 if counts.get("scenario_stop", 0) else 0

    return Score(
        scenario_id=scenario.id,
        passed=passed,
        impact_score=impact_score,
        detection_score=detection_score,
        recovery_score=recovery_score,
        summary={
            "event_counts": counts,
            "packets_received": received,
            "packets_forwarded": forwarded,
            "attack_events": injected,
        },
    )


def _read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events
