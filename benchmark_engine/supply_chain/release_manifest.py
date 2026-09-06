"""Strict, signed release manifests for the supply-chain artifact track.

The benchmark uses a deliberately local HMAC trust anchor.  It models the
release-acceptance boundary without claiming that a repository fixture key is
a production signing solution.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


SCHEMA_VERSION = 1
VALID_STATUSES = {"released", "clean", "revoked", "rollback"}


class ManifestError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def manifest_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return the exact signed fields; the signature never signs itself."""
    return {key: value for key, value in manifest.items() if key != "signature"}


def manifest_digest(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(manifest_payload(manifest))).hexdigest()


def tree_sha256(path: Path) -> str:
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    if not path.is_dir():
        raise ManifestError(f"Declared artifact source does not exist: {path}")
    digest = hashlib.sha256()
    for child in sorted(path.rglob("*")):
        if not child.is_file():
            continue
        digest.update(child.relative_to(path).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(child.read_bytes()).digest())
    return digest.hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML is required to load artifact manifests")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ManifestError(f"Manifest must be a mapping: {path}")
    validate_manifest(data)
    return data


def validate_manifest(manifest: dict[str, Any]) -> None:
    required = {
        "schema_version", "release_id", "profile_id", "artifact_type", "supplier_id",
        "version", "issued_at", "status", "compatibility", "content", "operations",
        "lifecycle", "signature",
    }
    missing = sorted(required - set(manifest))
    if missing:
        raise ManifestError(f"Manifest missing required fields: {', '.join(missing)}")
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise ManifestError(f"Unsupported manifest schema_version: {manifest['schema_version']}")
    if not isinstance(manifest["release_id"], str) or not manifest["release_id"]:
        raise ManifestError("release_id must be a non-empty string")
    if str(manifest["status"]) not in VALID_STATUSES:
        raise ManifestError(f"Invalid release status: {manifest['status']}")
    if not isinstance(manifest["compatibility"], dict) or not manifest["compatibility"]:
        raise ManifestError("compatibility must be a non-empty mapping")
    if not isinstance(manifest["content"], list) or not manifest["content"]:
        raise ManifestError("content must declare at least one immutable artifact")
    for item in manifest["content"]:
        if not isinstance(item, dict) or not isinstance(item.get("source"), str) or not isinstance(item.get("sha256"), str):
            raise ManifestError("Each content item requires source and sha256")
    if not isinstance(manifest["operations"], list) or not manifest["operations"]:
        raise ManifestError("operations must be a non-empty list")
    for op in manifest["operations"]:
        if not isinstance(op, dict) or not isinstance(op.get("type"), str) or not isinstance(op.get("target"), str):
            raise ManifestError("Each operation requires type and target")
    lifecycle = manifest["lifecycle"]
    if not isinstance(lifecycle, dict) or not isinstance(lifecycle.get("adapter"), str):
        raise ManifestError("lifecycle.adapter is required")
    signature = manifest["signature"]
    if not isinstance(signature, dict) or signature.get("algorithm") != "HMAC-SHA256":
        raise ManifestError("Only HMAC-SHA256 local benchmark signatures are supported")
    if not isinstance(signature.get("key_id"), str) or not isinstance(signature.get("value"), str):
        raise ManifestError("signature requires key_id and value")


def load_trust_anchors(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    anchors = data.get("hmac_sha256", {}) if isinstance(data, dict) else {}
    if not isinstance(anchors, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in anchors.items()):
        raise ManifestError(f"Invalid trust anchor file: {path}")
    return anchors


def verify_signature(manifest: dict[str, Any], anchors: dict[str, str]) -> bool:
    signature = manifest["signature"]
    key = anchors.get(signature["key_id"])
    if key is None:
        return False
    expected = hmac.new(bytes.fromhex(key), canonical_json(manifest_payload(manifest)), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, str(signature["value"]))


@dataclass(frozen=True)
class GateDecision:
    accepted: bool
    reasons: tuple[str, ...]
    manifest_digest: str
    content_digests: dict[str, str]

