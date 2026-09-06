#!/usr/bin/env python3
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_NOS3_ROOT = Path('/home/leejm/nos3')
SCENARIO_DIR_NAME = '.sp005_component_config_pollution'
STATE_NAME = 'state.json'
PROFILE_MANIFEST = 'sp005_profiles.json'
NUMBER_RE = re.compile(r'[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[Ee][-+]?\d+)?')


def main() -> None:
    args = parse_args()
    scenario_root = Path(__file__).resolve().parent
    nos3_root = resolve_nos3_root(args.nos3_root)
    profiles = load_profiles(scenario_root / PROFILE_MANIFEST)

    if args.list:
        for profile in profiles:
            print(f"{profile['id']}: {profile['title']}")
        return

    if args.restore:
        restore_all(nos3_root)
        return

    if args.all:
        apply_profiles(nos3_root, profiles)
        return

    if not args.profile:
        raise SystemExit('Pass --profile PROFILE_ID, --all, --list, or --restore.')

    profile = profile_by_id(profiles, args.profile)
    apply_profile(nos3_root, profile)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Apply SP005 component configuration pollution profiles to a NOS3 checkout.'
    )
    parser.add_argument('--nos3-root', type=Path, default=None, help='NOS3 root. Defaults to /home/leejm/nos3.')
    parser.add_argument('--profile', help='Profile id from sp005_profiles.json to apply.')
    parser.add_argument('--all', action='store_true', help='Apply all pollution profiles before one shared NOS3 rebuild.')
    parser.add_argument('--list', action='store_true', help='List available profiles.')
    parser.add_argument('--restore', action='store_true', help='Restore all files backed up by SP005.')
    return parser.parse_args()


def resolve_nos3_root(arg: Path | None) -> Path:
    candidates = []
    if arg is not None:
        candidates.append(arg)
    candidates.append(Path.cwd())
    candidates.append(DEFAULT_NOS3_ROOT)

    for candidate in candidates:
        root = candidate.expanduser().resolve()
        if (root / 'cfg/nos3_defs/targets.cmake').exists() and (root / 'components').exists():
            return root

    raise SystemExit('Could not locate NOS3 root. Pass --nos3-root /path/to/nos3.')


def load_profiles(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit(f'Missing profile manifest: {path}')
    return json.loads(path.read_text(encoding='utf-8'))


def profile_by_id(profiles: list[dict], profile_id: str) -> dict:
    for profile in profiles:
        if profile['id'] == profile_id:
            return profile
    raise SystemExit(f'Unknown profile: {profile_id}')


def scenario_dir(nos3_root: Path) -> Path:
    path = nos3_root / SCENARIO_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    (path / 'backups').mkdir(parents=True, exist_ok=True)
    (path / 'diffs').mkdir(parents=True, exist_ok=True)
    return path


def state_path(nos3_root: Path) -> Path:
    return scenario_dir(nos3_root) / STATE_NAME


def read_state(nos3_root: Path) -> dict:
    path = state_path(nos3_root)
    if not path.exists():
        return {'scenario': 'SP005', 'backups': {}, 'active_profile': None, 'active_profiles': [], 'history': []}
    return json.loads(path.read_text(encoding='utf-8'))


def normalize_active_profiles(state: dict) -> list[str]:
    active_profiles = state.get('active_profiles')
    if not isinstance(active_profiles, list):
        active_profiles = []

    legacy_active = state.get('active_profile')
    if legacy_active and legacy_active not in active_profiles:
        active_profiles.append(legacy_active)

    state['active_profiles'] = active_profiles
    state['active_profile'] = active_profiles[0] if len(active_profiles) == 1 else None
    return active_profiles


def write_state(nos3_root: Path, state: dict) -> None:
    state_path(nos3_root).write_text(json.dumps(state, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def ensure_under(root: Path, path: Path) -> None:
    root = root.resolve()
    path = path.resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise SystemExit(f'Refusing to touch path outside NOS3 root: {path}') from exc


def backup_once(nos3_root: Path, state: dict, path: Path, *, original_text: str | None = None) -> None:
    ensure_under(nos3_root, path)
    if not path.exists():
        raise SystemExit(f'Target config file does not exist: {path}')

    rel = str(path.relative_to(nos3_root))
    backups = state.setdefault('backups', {})
    if rel in backups:
        return

    backup_name = rel.replace('/', '__') + '.orig'
    backup_path = scenario_dir(nos3_root) / 'backups' / backup_name
    if original_text is None:
        shutil.copy2(path, backup_path)
    else:
        backup_path.write_text(original_text, encoding='utf-8')
    backups[rel] = {
        'backup': str(backup_path.relative_to(nos3_root)),
        'original_sha256': sha256_file(path),
        'backup_created_at': utc_now(),
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def mutate_profile_text(text: str, profile: dict) -> tuple[str, list[dict]]:
    if profile['mutator'] == 'anchored_numeric_token':
        return mutate_anchored_numeric_token(text, profile['anchor'], [profile])
    if profile['mutator'] == 'anchored_numeric_tokens':
        replacement_specs = []
        for replacement in profile['replacements']:
            spec = dict(profile)
            spec.update(replacement)
            replacement_specs.append(spec)
        return mutate_anchored_numeric_token(text, profile['anchor'], replacement_specs)
    if profile['mutator'] == 'xml_text':
        return mutate_xml_text(text, profile['xml_path'], profile['malicious_value'])
    raise SystemExit(f"Unsupported mutator: {profile['mutator']}")


def expected_original_profile(profile: dict) -> dict:
    """Return an inverse mutation profile using manifest-declared original values."""
    inverse = dict(profile)
    if profile['mutator'] == 'anchored_numeric_token':
        inverse['malicious_value'] = profile['expected_original']
    elif profile['mutator'] == 'anchored_numeric_tokens':
        inverse['replacements'] = []
        for replacement in profile['replacements']:
            restored = dict(replacement)
            restored['malicious_value'] = replacement['expected_original']
            inverse['replacements'].append(restored)
    elif profile['mutator'] == 'xml_text':
        inverse['malicious_value'] = profile['expected_original']
    else:
        raise SystemExit(f"Unsupported mutator: {profile['mutator']}")
    return inverse


def apply_profile(nos3_root: Path, profile: dict, *, batch: bool = False) -> None:
    state = read_state(nos3_root)
    active_profiles = normalize_active_profiles(state)
    if profile['id'] in active_profiles:
        raise SystemExit(f"SP005 profile already applied: {profile['id']}. Run --restore before applying it again.")

    source_path = nos3_root / profile['path']
    before = source_path.read_text(encoding='utf-8')
    after, changes = mutate_profile_text(before, profile)

    if before == after:
        # A prior interrupted/legacy prepare may have left a source field in
        # its malicious value without preserving SP005 state.  Reconstruct the
        # manifest-declared original for the backup, then register the profile
        # as active rather than failing or backing up the polluted source.
        reconstructed_original, _ = mutate_profile_text(before, expected_original_profile(profile))
        if reconstructed_original == before:
            raise SystemExit('Mutation produced no file change; refusing to continue.')
        backup_once(nos3_root, state, source_path, original_text=reconstructed_original)
        after = before
        changes = [{
            'reconciled_existing_pollution': True,
            'source_path': str(source_path),
            'expected_original_reconstructed_for_backup': True,
        }]
    else:
        backup_once(nos3_root, state, source_path)
        source_path.write_text(after, encoding='utf-8')
    diff_text = ''.join(difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=profile['path'] + '.before',
        tofile=profile['path'] + '.after',
    ))
    diff_path = scenario_dir(nos3_root) / 'diffs' / f"{profile['id']}.diff"
    diff_path.write_text(diff_text, encoding='utf-8')

    active_profiles.append(profile['id'])
    state['active_profiles'] = active_profiles
    state['active_profile'] = None if batch or len(active_profiles) != 1 else profile['id']
    state.setdefault('history', []).append({
        'profile': profile['id'],
        'applied_at': utc_now(),
        'path': profile['path'],
        'changes': changes,
        'diff': str(diff_path.relative_to(nos3_root)),
        'source_sha256_after': sha256_file(source_path),
    })
    write_state(nos3_root, state)

    if not batch:
        print(f"Applied SP005 profile: {profile['id']}")
        print(f"Changed source config: {source_path}")
        print(f"Wrote diff evidence: {diff_path}")
        print('Next: run make config && make fsw && make sim, restart NOS3/cFS/sims, then run sp005_verify.rb.')


def apply_profiles(nos3_root: Path, profiles: list[dict]) -> None:
    applied = []
    state = read_state(nos3_root)
    active_profiles = set(normalize_active_profiles(state))
    for profile in profiles:
        if profile['id'] in active_profiles:
            print(f"SP005 profile already prepared: {profile['id']}")
            continue
        apply_profile(nos3_root, profile, batch=True)
        applied.append(profile['id'])
        active_profiles.add(profile['id'])

    state = read_state(nos3_root)
    active_profiles = normalize_active_profiles(state)
    state['active_profile'] = None if len(active_profiles) != 1 else active_profiles[0]
    write_state(nos3_root, state)

    print('Applied all SP005 pollution profiles:')
    for profile_id in applied:
        print(f"  {profile_id}")
    print('Next: run one shared make config && make fsw && make sim, restart NOS3/cFS/sims, then verify one profile at a time with SP005_PROFILE.')


def mutate_anchored_numeric_token(text: str, anchor: str, specs: list[dict]) -> tuple[str, list[dict]]:
    lines = text.splitlines(keepends=True)
    matches = [i for i, line in enumerate(lines) if anchor in line]
    selected_match = specs[0].get('line_match_index') if specs else None
    if selected_match is None:
        if len(matches) != 1:
            raise SystemExit(f"Expected exactly one line containing anchor {anchor!r}, found {len(matches)}. Add line_match_index to the profile.")
        selected_match = 0
    selected_match = int(selected_match)
    if selected_match < 0 or selected_match >= len(matches):
        raise SystemExit(f"line_match_index {selected_match} out of range for anchor {anchor!r}; found {len(matches)} matches")

    index = matches[selected_match]
    line = lines[index]
    numbers = list(NUMBER_RE.finditer(line.split('!', 1)[0]))
    if not numbers:
        raise SystemExit(f"No numeric tokens found before comment anchor {anchor!r}")

    replacements = []
    for spec in sorted(specs, key=lambda item: item['token_index'], reverse=True):
        token_index = int(spec['token_index'])
        if token_index < 0 or token_index >= len(numbers):
            raise SystemExit(f"Token index {token_index} out of range for anchor {anchor!r}")
        match = numbers[token_index]
        current = match.group(0)
        replacements.append({
            'line': index + 1,
            'line_match_index': selected_match,
            'anchor': anchor,
            'token_index': token_index,
            'old': current,
            'new': str(spec['malicious_value']),
        })
        line = line[:match.start()] + str(spec['malicious_value']) + line[match.end():]

    lines[index] = line
    return ''.join(lines), sorted(replacements, key=lambda item: item['token_index'])


def mutate_xml_text(text: str, xml_path: list[str], malicious_value: str) -> tuple[str, list[dict]]:
    try:
        root = ET.fromstring(text)
        node = root
        for part in xml_path:
            found = node.find(part)
            if found is None:
                raise ValueError(f"XML path not found: {'/'.join(xml_path)}")
            node = found

        current = (node.text or '').strip()
    except (ET.ParseError, ValueError):
        return mutate_xml_text_by_regex(text, xml_path, malicious_value)

    old_fragment = f"><{xml_path[-1]}>{current}</{xml_path[-1]}><"
    new_fragment = f"><{xml_path[-1]}>{malicious_value}</{xml_path[-1]}><"
    if old_fragment in text:
        updated = text.replace(old_fragment, new_fragment, 1)
    else:
        pattern = re.compile(rf"(<{re.escape(xml_path[-1])}>)(.*?)(</{re.escape(xml_path[-1])}>)")
        updated, count = pattern.subn(rf"\g<1>{malicious_value}\g<3>", text, count=1)
        if count != 1:
            raise SystemExit(f"Could not replace XML text for {'/'.join(xml_path)}")

    return updated, [{
        'xml_path': '/'.join(xml_path),
        'old': current,
        'new': str(malicious_value),
    }]


def mutate_xml_text_by_regex(text: str, xml_path: list[str], malicious_value: str) -> tuple[str, list[dict]]:
    tag = xml_path[-1]
    patterns = []
    if len(xml_path) >= 2:
        parent = xml_path[-2]
        patterns.append(re.compile(
            rf"(<{re.escape(parent)}>.*?<{re.escape(tag)}>\s*)([^<]+?)(\s*</{re.escape(tag)}>.*?</{re.escape(parent)}>)",
            re.DOTALL,
        ))
    patterns.append(re.compile(rf"(<{re.escape(tag)}>\s*)([^<]+?)(\s*</{re.escape(tag)}>)", re.DOTALL))

    for pattern in patterns:
        match = pattern.search(text)
        if not match:
            continue
        current = match.group(2).strip()
        updated = text[:match.start(2)] + str(malicious_value) + text[match.end(2):]
        return updated, [{
            'xml_path': '/'.join(xml_path),
            'old': current,
            'new': str(malicious_value),
            'parser_fallback': True,
        }]

    raise SystemExit(f"Could not replace XML text for {'/'.join(xml_path)}")


def restore_all(nos3_root: Path) -> None:
    state = read_state(nos3_root)
    backups = state.get('backups', {})
    if not backups:
        print('No SP005 backups recorded; nothing to restore.')
        return

    restored = []
    for rel, metadata in sorted(backups.items()):
        target = nos3_root / rel
        backup = nos3_root / metadata['backup']
        ensure_under(nos3_root, target)
        ensure_under(nos3_root, backup)
        if not backup.exists():
            raise SystemExit(f"Recorded backup is missing: {backup}")
        shutil.copy2(backup, target)
        actual = sha256_file(target)
        expected = metadata['original_sha256']
        if actual != expected:
            raise SystemExit(f"Restore checksum mismatch for {target}: {actual} != {expected}")
        restored.append(rel)

    state['active_profile'] = None
    state['active_profiles'] = []
    state.setdefault('history', []).append({'restored_at': utc_now(), 'restored': restored})
    write_state(nos3_root, state)

    print('Restored SP005 component configuration files:')
    for rel in restored:
        print(f"  {rel}")
    print('Next: run make config && make fsw && make sim and restart NOS3/cFS/sims to return runtime behavior to normal.')


if __name__ == '__main__':
    main()
