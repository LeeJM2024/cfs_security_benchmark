"""Release acceptance gate: provenance, immutable content, status and compatibility."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmark_engine.supply_chain.release_manifest import (
    GateDecision, ManifestError, load_trust_anchors, manifest_digest, tree_sha256, verify_signature,
)


def evaluate_release(
    manifest: dict[str, Any], *, repo_root: Path, trust_anchor_path: Path,
    platform_versions: dict[str, str] | None = None, minimum_versions: dict[str, str] | None = None,
) -> GateDecision:
    """Evaluate without changing a release target.

    The gate intentionally binds status and compatibility in addition to hashes;
    a correctly hashed revoked or old release is still rejected.
    """
    reasons: list[str] = []
    content_digests: dict[str, str] = {}
    try:
        anchors = load_trust_anchors(trust_anchor_path)
        if not verify_signature(manifest, anchors):
            reasons.append("signature verification failed")
    except (OSError, ValueError, ManifestError) as error:
        reasons.append(f"trust-anchor error: {error}")

    if manifest.get("status") == "revoked":
        reasons.append("release is revoked")
    if manifest.get("status") == "rollback":
        reasons.append("release is marked rollback/old and is not accepted by default")

    for item in manifest.get("content", []):
        source = (repo_root / str(item["source"])).resolve()
        try:
            source.relative_to(repo_root.resolve())
            actual = tree_sha256(source)
            content_digests[str(item["source"])] = actual
            if actual != item["sha256"]:
                reasons.append(f"content hash mismatch: {item['source']}")
        except (OSError, ManifestError, ValueError) as error:
            reasons.append(f"content unavailable: {item.get('source')}: {error}")

    versions = platform_versions or {}
    for name, expected in dict(manifest.get("compatibility", {})).items():
        actual = versions.get(str(name))
        if actual is not None and actual != str(expected):
            reasons.append(f"incompatible {name}: release requires {expected}, target is {actual}")
    for name, minimum in (minimum_versions or {}).items():
        if name == "release_version" and _version_lt(str(manifest.get("version", "0")), minimum):
            reasons.append(f"release version {manifest.get('version')} is below policy minimum {minimum}")

    return GateDecision(not reasons, tuple(reasons), manifest_digest(manifest), content_digests)


def _version_lt(actual: str, minimum: str) -> bool:
    def tokens(value: str) -> tuple[int, ...]:
        return tuple(int(part) if part.isdigit() else 0 for part in value.split("."))
    return tokens(actual) < tokens(minimum)
