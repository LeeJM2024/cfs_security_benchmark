"""Atomic, path-confined application and restoration of release operations."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any

from benchmark_engine.supply_chain.release_manifest import tree_sha256


class TransactionError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass
class ArtifactTransaction:
    manifest: dict[str, Any]
    repo_root: Path
    target_root: Path
    state_root: Path

    def __post_init__(self) -> None:
        self.repo_root = self.repo_root.resolve()
        self.target_root = self.target_root.resolve()
        self.state_root = self.state_root.resolve()
        self.tx_root = self.state_root / self.manifest["release_id"]
        self.ledger_path = self.tx_root / "transaction.json"

    def apply(self) -> dict[str, Any]:
        """Snapshot every declared target before any write, then apply all operations.

        On every failure the pre-transaction filesystem state is restored before
        the exception leaves this method.  Operations may only target paths
        below target_root and copy sources below repo_root.
        """
        if self.ledger_path.exists():
            existing = json.loads(self.ledger_path.read_text(encoding="utf-8"))
            if existing.get("status") != "rolled_back":
                raise TransactionError(f"Release transaction already exists: {self.ledger_path}; rollback it first")
            archive = self.state_root / f"{self.manifest['release_id']}.rolled_back.{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
            shutil.move(str(self.tx_root), str(archive))
        self.tx_root.mkdir(parents=True, exist_ok=False)
        targets = self._declared_targets()
        ledger: dict[str, Any] = {
            "release_id": self.manifest["release_id"], "started_at": _now(), "target_root": str(self.target_root),
            "status": "snapshotting", "targets": [self._snapshot(path) for path in targets], "operations": [],
        }
        self._write_ledger(ledger)
        try:
            ledger["status"] = "applying"
            self._write_ledger(ledger)
            for operation in self.manifest["operations"]:
                result = self._apply_operation(operation)
                ledger["operations"].append(result)
                self._write_ledger(ledger)
            ledger["status"] = "applied"
            ledger["applied_at"] = _now()
            self._write_ledger(ledger)
            return ledger
        except Exception as error:
            ledger["apply_error"] = f"{type(error).__name__}: {error}"
            self._write_ledger(ledger)
            rollback = self.rollback()
            if not rollback["restored"]:
                raise TransactionError(f"apply failed and automatic rollback was incomplete: {error}") from error
            raise TransactionError(f"apply failed; automatic rollback completed: {error}") from error

    def rollback(self) -> dict[str, Any]:
        if not self.ledger_path.exists():
            raise TransactionError(f"No transaction ledger found: {self.ledger_path}")
        ledger = json.loads(self.ledger_path.read_text(encoding="utf-8"))
        failures: list[str] = []
        for snapshot in reversed(ledger.get("targets", [])):
            try:
                self._restore_snapshot(snapshot)
            except Exception as error:  # preserve every attempted restore in evidence
                failures.append(f"{snapshot.get('target')}: {type(error).__name__}: {error}")
        ledger["rollback_at"] = _now()
        ledger["rollback_failures"] = failures
        ledger["status"] = "rolled_back" if not failures else "rollback_incomplete"
        self._write_ledger(ledger)
        return {"restored": not failures, "failures": failures, "ledger": str(self.ledger_path)}

    def _declared_targets(self) -> list[Path]:
        targets: list[Path] = []
        seen: set[Path] = set()
        for operation in self.manifest["operations"]:
            target = self._target(str(operation["target"]))
            if target not in seen:
                seen.add(target)
                targets.append(target)
        return targets

    def _target(self, relative: str) -> Path:
        path = (self.target_root / relative).resolve()
        try:
            path.relative_to(self.target_root)
        except ValueError as error:
            raise TransactionError(f"Refusing target outside target root: {relative}") from error
        return path

    def _source(self, relative: str) -> Path:
        path = (self.repo_root / relative).resolve()
        try:
            path.relative_to(self.repo_root)
        except ValueError as error:
            raise TransactionError(f"Refusing source outside repository: {relative}") from error
        if not path.exists():
            raise TransactionError(f"Release source does not exist: {relative}")
        return path

    def _snapshot(self, target: Path) -> dict[str, Any]:
        rel = target.relative_to(self.target_root).as_posix()
        snapshot = self.tx_root / "snapshot" / rel
        if not target.exists():
            return {"target": rel, "exists": False}
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        if target.is_dir():
            shutil.copytree(target, snapshot)
            return {"target": rel, "exists": True, "kind": "directory", "backup": str(snapshot.relative_to(self.tx_root)), "sha256": tree_sha256(target)}
        shutil.copy2(target, snapshot)
        return {"target": rel, "exists": True, "kind": "file", "backup": str(snapshot.relative_to(self.tx_root)), "sha256": _sha256(target)}

    def _restore_snapshot(self, snapshot: dict[str, Any]) -> None:
        target = self._target(str(snapshot["target"]))
        if target.exists():
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
        if not snapshot.get("exists"):
            return
        backup = (self.tx_root / str(snapshot["backup"])).resolve()
        if snapshot["kind"] == "directory":
            shutil.copytree(backup, target)
            actual = tree_sha256(target)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup, target)
            actual = _sha256(target)
        if actual != snapshot["sha256"]:
            raise TransactionError(f"restore checksum mismatch for {target}")

    def _apply_operation(self, operation: dict[str, Any]) -> dict[str, Any]:
        kind = str(operation["type"])
        target = self._target(str(operation["target"]))
        if kind == "copy_file":
            source = self._source(str(operation["source"]))
            if not source.is_file():
                raise TransactionError(f"copy_file source is not a file: {source}")
            expected = str(operation["sha256"])
            if _sha256(source) != expected:
                raise TransactionError(f"copy_file source digest mismatch: {source}")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            actual = _sha256(target)
        elif kind == "copy_tree":
            source = self._source(str(operation["source"]))
            if not source.is_dir():
                raise TransactionError(f"copy_tree source is not a directory: {source}")
            expected = str(operation["sha256"])
            if tree_sha256(source) != expected:
                raise TransactionError(f"copy_tree source digest mismatch: {source}")
            if target.exists():
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, target)
            actual = tree_sha256(target)
        elif kind == "copy_tree_contents":
            source = self._source(str(operation["source"]))
            if not source.is_dir():
                raise TransactionError(f"copy_tree_contents source is not a directory: {source}")
            expected = str(operation["sha256"])
            if tree_sha256(source) != expected:
                raise TransactionError(f"copy_tree_contents source digest mismatch: {source}")
            target.mkdir(parents=True, exist_ok=True)
            for child in source.rglob("*"):
                destination = target / child.relative_to(source)
                if child.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(child, destination)
            actual = tree_sha256(target)
        elif kind == "cmake_add_mission_app":
            component = str(operation["component"])
            before = target.read_text(encoding="utf-8")
            marker = "list(APPEND MISSION_GLOBAL_APPLIST"
            start = before.find(marker)
            end = before.find("\n)", start) if start >= 0 else -1
            if start < 0 or end < 0:
                raise TransactionError(f"MISSION_GLOBAL_APPLIST block was not found in {target}")
            existing = before[start:end]
            # CMake list entries are normally indented.  Compare the logical
            # list values, not their source formatting, so an app previously
            # installed by another benchmark track is not appended again.
            existing_entries = {line.strip() for line in existing.splitlines()}
            if component not in existing_entries:
                indentation = str(operation.get("indentation", "        "))
                after = before[:end] + f"\n{indentation}{component}" + before[end:]
                target.write_text(after, encoding="utf-8")
            else:
                after = before
            actual = _sha256(target)
        elif kind == "append_unique_line":
            line = str(operation["line"])
            before = target.read_text(encoding="utf-8") if target.exists() else ""
            if line not in before.splitlines():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(before.rstrip("\n") + "\n" + line + "\n", encoding="utf-8")
            actual = _sha256(target)
        elif kind == "text_replace":
            before = target.read_text(encoding="utf-8")
            original, replacement = str(operation["original"]), str(operation["replacement"])
            if before.count(original) != 1:
                raise TransactionError(f"text replacement requires exactly one match in {target}")
            target.write_text(before.replace(original, replacement, 1), encoding="utf-8")
            actual = _sha256(target)
        else:
            raise TransactionError(f"Unsupported release operation: {kind}")
        return {"type": kind, "target": str(operation["target"]), "result_sha256": actual}

    def _write_ledger(self, ledger: dict[str, Any]) -> None:
        self.ledger_path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
