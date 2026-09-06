from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SupplyChainEvidence:
    """Common evidence envelope; PASS remains attack-success semantics."""

    profile_id: str
    passed: bool = False
    artifact_accepted: bool = False
    benign_contract_passed: bool = False
    dormancy_observed: bool = False
    trigger_observed: bool = False
    coordination_observed: bool = False
    payload_invoked: bool = False
    mission_effect_observed: bool = False
    recovery_observed: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "passed": self.passed,
            "artifact_accepted": self.artifact_accepted,
            "benign_contract_passed": self.benign_contract_passed,
            "dormancy_observed": self.dormancy_observed,
            "trigger_observed": self.trigger_observed,
            "coordination_observed": self.coordination_observed,
            "payload_invoked": self.payload_invoked,
            "mission_effect_observed": self.mission_effect_observed,
            "recovery_observed": self.recovery_observed,
            "details": self.details,
        }
