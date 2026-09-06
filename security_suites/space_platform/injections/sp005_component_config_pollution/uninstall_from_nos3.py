#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

DEFAULT_NOS3_ROOT = Path('/home/leejm/nos3')
DEFAULT_OPERATOR_CONTAINER = 'cosmos-openc3-operator-1'
VERIFY_SCRIPT_NAME = 'sp005_verify.rb'
PROFILE_MANIFEST_NAME = 'sp005_profiles.json'
STATE_DIR_NAME = '.sp005_component_config_pollution'


def main() -> None:
    args = parse_args()
    nos3_root = resolve_nos3_root(args.nos3_root)
    restore_backups(nos3_root)
    remove_procedures(nos3_root)
    remove_container_files(args.operator_container)
    print('SP005 component configuration pollution integration uninstalled.')
    print('Next: run `make config && make fsw` before the next normal NOS3 launch.')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Uninstall SP005 benchmark scripts and restore polluted component configs.')
    parser.add_argument('--nos3-root', type=Path, default=None, help='NOS3 root. Defaults to /home/leejm/nos3.')
    parser.add_argument('--operator-container', default=DEFAULT_OPERATOR_CONTAINER)
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


def ensure_under(root: Path, path: Path) -> None:
    root = root.resolve()
    path = path.resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise SystemExit(f'Refusing to touch path outside NOS3 root: {path}') from exc


def restore_backups(nos3_root: Path) -> None:
    state_dir = nos3_root / STATE_DIR_NAME
    state_path = state_dir / 'state.json'
    if not state_path.exists():
        print('No SP005 state file found; no component config backups to restore.')
        return

    import json
    import hashlib

    state = json.loads(state_path.read_text(encoding='utf-8'))
    restored = []
    for rel, metadata in sorted(state.get('backups', {}).items()):
        target = nos3_root / rel
        backup = nos3_root / metadata['backup']
        ensure_under(nos3_root, target)
        ensure_under(nos3_root, backup)
        if not backup.exists():
            raise SystemExit(f'Recorded SP005 backup missing: {backup}')
        shutil.copy2(backup, target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if digest != metadata['original_sha256']:
            raise SystemExit(f'Restore checksum mismatch for {target}')
        restored.append(rel)

    # The shared SP clean-phase preflight reads active_profiles.  Clear both
    # the current list and its legacy singular representation after a verified
    # filesystem restore.
    state['active_profiles'] = []
    state['active_profile'] = None
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    if restored:
        print('Restored SP005 component config backups:')
        for rel in restored:
            print(f'  {rel}')
    else:
        print('SP005 state had no config backups recorded.')


def remove_procedures(nos3_root: Path) -> None:
    candidates = []
    for base in [
        nos3_root / 'gsw/cosmos/config/targets/MISSION/procedures',
        nos3_root / 'gsw/cosmos/outputs/tmp/config/targets/MISSION/procedures',
    ]:
        for name in [VERIFY_SCRIPT_NAME, PROFILE_MANIFEST_NAME]:
            candidates.append(base / name)

    for path in candidates:
        if not path.exists():
            print(f'Already absent: {path}')
            continue
        backup = path.with_suffix(path.suffix + '.sp005.bak')
        if backup.exists():
            shutil.copy2(backup, path)
            backup.unlink()
            print(f'Restored pre-existing procedure artifact: {path}')
        else:
            ensure_under(nos3_root, path)
            path.unlink()
            print(f'Removed SP005 procedure artifact: {path}')


def remove_container_files(container: str) -> None:
    result = subprocess.run(
        ['docker', 'ps', '--format', '{{.Names}}'],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        print(f'Skipped container cleanup; docker ps failed: {result.stderr.strip()}')
        return
    containers = {line.strip() for line in result.stdout.splitlines()}
    if container not in containers:
        print(f'Skipped container cleanup; {container} is not running.')
        return
    result = subprocess.run(
        ['docker', 'exec', container, 'rm', '-f', f'/tmp/{VERIFY_SCRIPT_NAME}', f'/tmp/{PROFILE_MANIFEST_NAME}'],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode == 0:
        print(f'Removed SP005 files from {container}:/tmp')
    else:
        print(f'Skipped container cleanup; docker exec failed: {result.stderr.strip()}')


if __name__ == '__main__':
    main()
