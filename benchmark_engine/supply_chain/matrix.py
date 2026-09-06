from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - dependency is declared by the project
    yaml = None


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCENARIO_ROOT = PROJECT_ROOT / "security_suites" / "supply_chain" / "scenarios"


@dataclass(frozen=True)
class SupplyChainProfile:
    profile_id: str
    track: str
    payloads: tuple[str, ...] = ()
    status: str = "scaffold"
    metadata: dict[str, Any] | None = None


def load_matrix() -> list[SupplyChainProfile]:
    """Load the scaffold profile index without executing any live attack."""
    if yaml is None:
        raise RuntimeError("PyYAML is required to load the supply-chain matrix")

    profiles: list[SupplyChainProfile] = []
    app_data = _load_yaml(SCENARIO_ROOT / "app_architectures.yaml")
    payload_data = _load_yaml(SCENARIO_ROOT / "payloads.yaml")
    payload_ids = tuple(str(item["id"]) for item in payload_data.get("profiles", []))
    for item in app_data.get("profiles", []):
        profiles.append(
            SupplyChainProfile(
                profile_id=str(item["id"]),
                track="app",
                payloads=payload_ids,
                status=str(item.get("implementation_status", "scaffold")),
                metadata=dict(item),
            )
        )

    artifact_data = _load_yaml(SCENARIO_ROOT / "artifact_track.yaml")
    for item in artifact_data.get("profiles", []):
        profiles.append(
            SupplyChainProfile(
                profile_id=str(item["id"]),
                track="artifact",
                status=str(item.get("implementation_status", "scaffold")),
                metadata=dict(item),
            )
        )
    return profiles


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"supply-chain scenario must be a mapping: {path}")
    return data
