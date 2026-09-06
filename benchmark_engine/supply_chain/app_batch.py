"""APP-track preparation and cleanup adapters for the supply-chain batch.

The real NOS3 integration remains owned by the existing supply-chain
installer/uninstaller.  This module only gives the combined batch a small,
structured interface and preserves their subprocess evidence.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SUITE_ROOT = PROJECT_ROOT / "security_suites" / "supply_chain"


def prepare(*, nos3_root: Path, prepare_valid_novatel: bool, dry_run: bool = False) -> dict[str, Any]:
    command = [sys.executable, str(SUITE_ROOT / "install_into_nos3.py"), "--nos3-root", str(nos3_root)]
    if prepare_valid_novatel:
        command.append("--prepare-valid-novatel")
    return _invoke("prepare", command, dry_run)


def clean(*, nos3_root: Path, dry_run: bool = False) -> dict[str, Any]:
    command = [sys.executable, str(SUITE_ROOT / "uninstall_from_nos3.py"), "--nos3-root", str(nos3_root)]
    return _invoke("clean", command, dry_run)


def _invoke(phase: str, command: list[str], dry_run: bool) -> dict[str, Any]:
    if dry_run:
        return {"phase": phase, "passed": True, "dry_run": True, "command": command}
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    return {
        "phase": phase,
        "passed": completed.returncode == 0,
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }
