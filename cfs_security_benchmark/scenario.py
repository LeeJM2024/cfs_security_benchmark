from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json


try:
    import yaml
except ImportError:  # pragma: no cover - fallback for minimal Python installs
    yaml = None


REQUIRED_DESCRIPTION_FIELDS = (
    "attack_entry",
    "affected_component",
    "cps_type",
    "security_consequence",
    "recovery_strategy",
    "injection_method",
)


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    domain: str
    description: dict[str, str]
    attack: dict[str, Any]
    metrics: list[str] = field(default_factory=list)
    pass_criteria: dict[str, Any] = field(default_factory=dict)
    notes: str = ""

    @property
    def attack_type(self) -> str:
        return str(self.attack.get("type", "observe"))

    def validate(self) -> None:
        missing = [key for key in REQUIRED_DESCRIPTION_FIELDS if not self.description.get(key)]
        if missing:
            joined = ", ".join(missing)
            raise ValueError(f"scenario {self.id} missing description field(s): {joined}")
        if not self.id:
            raise ValueError("scenario id is required")
        if not self.name:
            raise ValueError(f"scenario {self.id} missing name")
        if not self.domain:
            raise ValueError(f"scenario {self.id} missing domain")
        if not isinstance(self.attack, dict):
            raise ValueError(f"scenario {self.id} attack must be a mapping")


def load_scenario(path: str | Path) -> Scenario:
    source = Path(path)
    raw_text = source.read_text(encoding="utf-8")
    data: dict[str, Any]

    if source.suffix.lower() in {".yaml", ".yml"}:
        if yaml is None:
            data = _minimal_yaml_load(raw_text)
        else:
            data = yaml.safe_load(raw_text)
    elif source.suffix.lower() == ".json":
        data = json.loads(raw_text)
    else:
        raise ValueError(f"unsupported scenario file type: {source}")

    scenario = Scenario(
        id=str(data["id"]),
        name=str(data["name"]),
        domain=str(data["domain"]),
        description=dict(data.get("description", {})),
        attack=dict(data.get("attack", {})),
        metrics=list(data.get("metrics", [])),
        pass_criteria=dict(data.get("pass_criteria", {})),
        notes=str(data.get("notes", "")),
    )
    scenario.validate()
    return scenario


def load_scenarios(directory: str | Path) -> list[Scenario]:
    root = Path(directory)
    paths = sorted([*root.glob("*.yaml"), *root.glob("*.yml"), *root.glob("*.json")])
    return [load_scenario(path) for path in paths]


def _minimal_yaml_load(text: str) -> dict[str, Any]:
    """Small fallback loader for the simple scenario files in this repository."""
    result: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, result)]

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if line.startswith("- "):
            value = _parse_scalar(line[2:].strip())
            if isinstance(parent, list):
                parent.append(value)
            else:
                raise ValueError("minimal YAML parser only supports list items under lists")
            continue

        if ":" not in line:
            raise ValueError(f"cannot parse YAML line: {raw_line}")

        key, raw_value = line.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()

        if raw_value == "":
            next_container: dict[str, Any] | list[Any]
            next_container = [] if _next_significant_line_is_list(text, raw_line) else {}
            parent[key] = next_container
            stack.append((indent, next_container))
        else:
            parent[key] = _parse_scalar(raw_value)

    return result


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.lower() == "null":
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value


def _next_significant_line_is_list(text: str, current_line: str) -> bool:
    lines = text.splitlines()
    try:
        start = lines.index(current_line) + 1
    except ValueError:
        return False
    current_indent = len(current_line) - len(current_line.lstrip(" "))
    for line in lines[start:]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        return indent > current_indent and line.strip().startswith("- ")
    return False
