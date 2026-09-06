#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_NOS3_ROOT = Path('/home/leejm/nos3')
DEFAULT_OPERATOR_CONTAINER = 'cosmos-openc3-operator-1'
VERIFY_SCRIPT_NAME = 'sp005_verify.rb'
PROFILE_MANIFEST_NAME = 'sp005_profiles.json'
APPLY_SCRIPT_NAME = 'apply_profile.py'
UNINSTALL_SCRIPT_NAME = 'uninstall_from_nos3.py'


def main() -> None:
    args = parse_args()
    nos3_root = resolve_nos3_root(args.nos3_root)
    integration_root = Path(__file__).resolve().parent

    for name in [VERIFY_SCRIPT_NAME, PROFILE_MANIFEST_NAME, APPLY_SCRIPT_NAME, UNINSTALL_SCRIPT_NAME]:
        require_file(integration_root / name)

    install_procedures(integration_root, nos3_root)
    copy_to_operator(integration_root / VERIFY_SCRIPT_NAME, args.operator_container, f'/tmp/{VERIFY_SCRIPT_NAME}')
    copy_to_operator(integration_root / PROFILE_MANIFEST_NAME, args.operator_container, f'/tmp/{PROFILE_MANIFEST_NAME}')

    if args.apply_profiles:
        apply_all_profiles(integration_root, nos3_root)
        print('SP005 component configuration pollution integration prepared.')
    else:
        print('SP005 component configuration pollution assets installed; source/simulator configuration remains unchanged.')
    print('')
    print('Workflow:')
    print('  1. Install assets only:       this command (safe for clean-baseline runs)')
    print(f'  2. Prepare SP005 explicitly: python3 -m benchmark_engine.space_platform.verify_all --prepare-sp005 --nos3-root {nos3_root}')
    print('  3. Build/restart once:        cd NOS3 root && make config && make fsw && make sim')
    print(f'  4. Verify SP005 only:         python3 -m benchmark_engine.space_platform.verify_all --phase sp005 --nos3-root {nos3_root}')
    print(f'  5. Restore after SP005:       python3 {integration_root / APPLY_SCRIPT_NAME} --nos3-root {nos3_root} --restore')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Install SP005 component configuration pollution benchmark scripts into NOS3/COSMOS.'
    )
    parser.add_argument('--nos3-root', type=Path, default=None, help='NOS3 root. Defaults to /home/leejm/nos3.')
    parser.add_argument('--operator-container', default=DEFAULT_OPERATOR_CONTAINER)
    parser.add_argument(
        '--apply-profiles',
        action='store_true',
        help='apply all SP005 source/simulator pollution profiles (normally use verify_all --prepare-sp005 instead)',
    )
    return parser.parse_args()


def resolve_nos3_root(arg: Path | None) -> Path:
    candidates = []
    if arg is not None:
        candidates.append(arg)
    candidates.append(Path.cwd())
    candidates.append(DEFAULT_NOS3_ROOT)
    for candidate in candidates:
        root = candidate.expanduser().resolve()
        if (root / 'cfg/nos3_defs/targets.cmake').exists() and (root / 'gsw/cosmos').exists():
            return root
    raise SystemExit('Could not locate NOS3 root. Pass --nos3-root /path/to/nos3.')


def require_file(path: Path) -> None:
    if not path.exists():
        raise SystemExit(f'Missing SP005 artifact: {path}')


def install_procedures(integration_root: Path, nos3_root: Path) -> None:
    destinations = [nos3_root / 'gsw/cosmos/config/targets/MISSION/procedures']
    generated = nos3_root / 'gsw/cosmos/outputs/tmp/config/targets/MISSION/procedures'
    if generated.exists():
        destinations.append(generated)

    for dest_dir in destinations:
        dest_dir.mkdir(parents=True, exist_ok=True)
        for name in [VERIFY_SCRIPT_NAME, PROFILE_MANIFEST_NAME]:
            dest = dest_dir / name
            backup_once(dest)
            shutil.copy2(integration_root / name, dest)
            print(f'Installed SP005 COSMOS/OpenC3 procedure artifact: {dest}')


def backup_once(path: Path) -> None:
    if not path.exists():
        return
    backup = path.with_suffix(path.suffix + '.sp005.bak')
    if not backup.exists():
        shutil.copy2(path, backup)


def copy_to_operator(source: Path, container: str, destination: str) -> None:
    result = subprocess.run(
        ['docker', 'ps', '--format', '{{.Names}}'],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        print(f'Skipped container copy; docker ps failed: {result.stderr.strip()}')
        return
    containers = {line.strip() for line in result.stdout.splitlines()}
    if container not in containers:
        print(f'Skipped container copy; {container} is not running.')
        return
    result = subprocess.run(
        ['docker', 'cp', str(source), f'{container}:{destination}'],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode == 0:
        print(f'Copied into {container}:{destination}')
    else:
        print(f'Skipped container copy; docker cp failed: {result.stderr.strip()}')


def apply_all_profiles(integration_root: Path, nos3_root: Path) -> None:
    """Make SP005 payload application part of lifecycle prepare.

    SP005 modifies source and simulator configuration, so installation alone is
    not a valid prepared state.  The following normal NOS3 build/restart phase
    materializes these prepared sources into runtime configuration.
    """
    command = [sys.executable, str(integration_root / APPLY_SCRIPT_NAME), '--nos3-root', str(nos3_root), '--all']
    print(f'Preparing all SP005 pollution profiles: {" ".join(command)}')
    subprocess.run(command, check=True)


if __name__ == '__main__':
    main()
