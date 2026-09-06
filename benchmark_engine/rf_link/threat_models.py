from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a benchmark dependency
    yaml = None


THREAT_MODEL_IDS = ("trusted-domain", "cryptographic-boundary")


@dataclass(frozen=True)
class ProtectedPathProfile:
    direction: str
    source_alias: str
    destination_alias: str
    destination_port: int
    transport: str


@dataclass(frozen=True)
class ThreatModel:
    id: str
    name: str
    supported_links: tuple[str, ...]
    payload_format: str
    eavesdrop_success_if: str
    paths: dict[str, ProtectedPathProfile]

    def path_for(self, direction: str) -> ProtectedPathProfile:
        try:
            return self.paths[direction]
        except KeyError as error:
            raise ValueError(f"threat model {self.id} has no {direction} path") from error


def load_threat_model(model_id: str, root: Path) -> ThreatModel:
    if model_id not in THREAT_MODEL_IDS:
        choices = ", ".join(THREAT_MODEL_IDS)
        raise ValueError(f"unknown threat model {model_id!r}; choose one of {choices}")
    if yaml is None:
        raise RuntimeError("PyYAML is required to load RF-link threat-model profiles")

    source = root / "security_suites" / "rf_link" / "threat_models" / f"{model_id.replace('-', '_')}.yaml"
    data: dict[str, Any] = yaml.safe_load(source.read_text(encoding="utf-8"))
    paths = {
        str(direction): ProtectedPathProfile(
            direction=str(direction),
            source_alias=str(path["source_alias"]),
            destination_alias=str(path["destination_alias"]),
            destination_port=int(path["destination_port"]),
            transport=str(path["transport"]),
        )
        for direction, path in dict(data.get("radio_paths", {})).items()
    }
    return ThreatModel(
        id=str(data["id"]),
        name=str(data["name"]),
        supported_links=tuple(str(link) for link in data.get("supported_links", ())),
        payload_format=str(data.get("payload_format", "ccsds_plaintext")),
        eavesdrop_success_if=str(data.get("rf001", {}).get("attack_success_if", "packet_observed")),
        paths=paths,
    )
