from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import sys
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SPACE_INJECTIONS_ROOT = PROJECT_ROOT / "security_suites" / "space_platform" / "injections"
# Supply-chain implementation remains in benchmark_engine.supply_chain.  This
# registry only invokes its public batch entrypoint as one lifecycle domain.
DOMAIN_ORDER = ("rf_link", "space_platform", "ground_system", "supply_chain")


@dataclass(frozen=True)
class SpaceInjection:
    case_id: str
    root: Path
    install_script: Path
    verify_script: Path
    uninstall_script: Path


def space_injections() -> list[SpaceInjection]:
    injections: list[SpaceInjection] = []
    for root in sorted(SPACE_INJECTIONS_ROOT.glob("sp[0-9][0-9][0-9]_*")):
        case_id = root.name.split("_", 1)[0].upper()
        injection = SpaceInjection(
            case_id=case_id,
            root=root,
            install_script=root / "install_into_nos3.py",
            verify_script=root / f"{case_id.lower()}_verify.rb",
            uninstall_script=root / "uninstall_from_nos3.py",
        )
        missing = [path.name for path in (injection.install_script, injection.verify_script, injection.uninstall_script) if not path.is_file()]
        if missing:
            raise RuntimeError(f"{case_id} injection package is incomplete: missing {', '.join(missing)}")
        injections.append(injection)

    expected = {f"SP{index:03d}" for index in range(1, 9)}
    discovered = {injection.case_id for injection in injections}
    if discovered != expected:
        raise RuntimeError(f"expected injection packages {sorted(expected)}, found {sorted(discovered)}")
    return injections


def run_lifecycle(*, action: str, nos3_root: Path, domains: Iterable[str], dry_run: bool) -> bool:
    if action not in {"prep", "cleanup"}:
        raise ValueError(f"unsupported lifecycle action: {action}")

    selected = tuple(domains)
    invalid = set(selected) - set(DOMAIN_ORDER)
    if invalid:
        raise ValueError(f"unknown suite domains: {', '.join(sorted(invalid))}")

    print(f"lifecycle: {action}")
    print(f"NOS3 root: {nos3_root}")
    success = True
    ordered_domains = DOMAIN_ORDER if action == "prep" else tuple(reversed(DOMAIN_ORDER))
    for domain in ordered_domains:
        if domain not in selected:
            continue
        if domain == "supply_chain":
            phase = "prepare" if action == "prep" else "clean"
            command = [
                sys.executable, "-m", "benchmark_engine.supply_chain.batch",
                "--phase", phase, "--nos3-root", str(nos3_root),
            ]
            print(f"supply_chain: {' '.join(command)}")
            if dry_run:
                continue
            environment = os.environ.copy()
            existing_pythonpath = environment.get("PYTHONPATH", "")
            environment["PYTHONPATH"] = str(PROJECT_ROOT) + (os.pathsep + existing_pythonpath if existing_pythonpath else "")
            result = subprocess.run(command, check=False, env=environment)
            if result.returncode:
                success = False
                print(f"supply_chain: {action} failed with exit code {result.returncode}")
            continue
        if domain != "space_platform":
            print(f"{domain}: no install/uninstall hook registered")
            continue

        injections = space_injections()
        if action == "cleanup":
            injections = list(reversed(injections))
        for injection in injections:
            script = injection.install_script if action == "prep" else injection.uninstall_script
            command = [sys.executable, str(script), "--nos3-root", str(nos3_root)]
            print(f"{injection.case_id}: {' '.join(command)}")
            if dry_run:
                continue
            result = subprocess.run(command, check=False)
            if result.returncode:
                success = False
                print(f"{injection.case_id}: {action} failed with exit code {result.returncode}")
    return success
