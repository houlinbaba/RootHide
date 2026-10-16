#!/usr/bin/env python3
"""Collect/verify one approved private research artifact. Never execute iOS code."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import tarfile
import urllib.request
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
ANCHOR = '634c3f92ae1f940b1528c0cf68c929798b5a0440'
REPOSITORY = 'kulinichx/RootHide-Dev'
REF = 'refs/heads/codex/d1-single-person-634c3f9'
ALLOWED = {'.github/workflows/roothide.yml',
           '.github/scripts/package_single_person_research.py'}
CORE = ('libjailbreak.dylib', 'launchdhook.dylib', 'boomerang', 'jailbreakd', 'jbctl')
RECEIPTS = ('source-provenance.txt', 'd1-apple-components.json',
            'runtime-identity-tests.json', 'privilege-first-failure-tests.json')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(['git', '-c', 'safe.directory=' + ROOT.as_posix(),
                                    *args], cwd=ROOT)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def private_scope():
    expected = {'GITHUB_REPOSITORY': REPOSITORY, 'GITHUB_REF': REF,
                'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_ACTOR': 'kulinichx',
                'GITHUB_TRIGGERING_ACTOR': 'kulinichx', 'GITHUB_RUN_ATTEMPT': '1'}
    require(all(os.environ.get(k) == v for k, v in expected.items()),
            'Private repository/branch/actor/manual-first-attempt scope rejected')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    require(event['repository']['private'] is True, 'Dispatch repository is not private')
    require(event['repository']['full_name'] == REPOSITORY, 'Unexpected dispatch repository')
    require(str(event['inputs'].get('single_person_delivery', '')).lower() == 'true',
            'Delivery was not explicitly enabled')
    require(event['inputs'].get('build_mode') == 'full', 'Full build required')
    request = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY,
        headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'D1-private-research'})
    with urllib.request.urlopen(request, timeout=30) as response:
        repository = json.load(response)
    require(repository['private'] is True and repository['full_name'] == REPOSITORY,
            'Live repository privacy check failed')
    require(repository['default_branch'] != REF.removeprefix('refs/heads/'),
            'Delivery branch must not be the default branch')
    head = git('rev-parse', 'HEAD').decode().strip()
    require(head == os.environ['GITHUB_SHA'], 'Checkout does not match dispatched SHA')
    git('merge-base', '--is-ancestor', ANCHOR, head)
    changed = set(git('diff', '--name-only', ANCHOR, head).decode().splitlines())
    require(changed == ALLOWED, 'Source delta exceeds the two approved delivery files')
    trees = {}
    for label, revision in [('anchor', ANCHOR), ('final', head)]:
        entries = git('ls-tree', '-rz', '--full-tree', revision).split(b'\0')
        entries = [e for e in entries if e and e.split(b'\t', 1)[1].decode() not in ALLOWED]
        trees[label] = digest(b'\0'.join(entries))
    require(trees['anchor'] == trees['final'], 'Product/source/submodule object lists differ')
    status = json.loads((ROOT / 'docs/review/candidate-status.json').read_text())
    require(status['distributable'] is False and status['classification'] == 'compile-research'
            and status['F1'] == status['F3'] == 'FAIL', 'Stable distribution block changed')
    return {'runtime_anchor': ANCHOR, 'final_commit': head,
            'changed_paths': sorted(changed), 'source_tree_excluding_delivery_files': trees,
            'repository': REPOSITORY, 'ref': REF, 'actor': os.environ['GITHUB_ACTOR'],
            'run_id': os.environ['GITHUB_RUN_ID'], 'run_attempt': 1,
            'run_url': 'https://github.com/' + REPOSITORY + '/actions/runs/' + os.environ['GITHUB_RUN_ID'],
            'repository_private_checked_live': True, 'retention_days': 1}


def macho(data):
    """Read actual thin/fat Mach-O slices, including LC_UUID, without extraction."""
    if len(data) < 4:
        return None
    magic = data[:4]
    if magic in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf',
                 b'\xbe\xba\xfe\xca', b'\xbf\xba\xfe\xca'):
        endian = '>' if magic[:1] == b'\xca' else '<'
        wide = magic in (b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')
        count = struct.unpack_from(endian + 'I', data, 4)[0]
        size = 32 if wide else 20
        require(0 < count <= 32 and 8 + count * size <= len(data), 'Invalid fat header')
        result = {}
        for i in range(count):
            offset = 8 + i * size
            cpu, subtype = struct.unpack_from(endian + 'II', data, offset)
            start, length = struct.unpack_from(endian + ('QQ' if wide else 'II'), data, offset + 8)
            require(start >= 8 + count * size and length > 0 and start + length <= len(data),
                    'Invalid fat slice bounds')
            entry = macho(data[start:start + length])
            require(entry is not None and len(entry) == 1, 'Invalid fat slice')
            key, value = next(iter(entry.items()))
            require(value['cpu_type'] == cpu and value['cpu_subtype'] == subtype,
                    'Fat and thin architecture disagree')
            require(key not in result, 'Duplicate Mach-O architecture')
            result[key] = value
        return result
    thin = {b'\xcf\xfa\xed\xfe': ('<', 32), b'\xfe\xed\xfa\xcf': ('>', 32),
            b'\xce\xfa\xed\xfe': ('<', 28), b'\xfe\xed\xfa\xce': ('>', 28)}
    if magic not in thin:
        return None
    endian, header = thin[magic]
    require(len(data) >= header, 'Truncated Mach-O header')
    cpu, subtype, _, ncmds, sizecmds = struct.unpack_from(endian + 'IIIII', data, 4)
    require(header + sizecmds <= len(data) and ncmds <= sizecmds // 8, 'Invalid Mach-O commands')
    base_subtype = subtype & 0xffffff
    arch = ('arm64e' if base_subtype == 2 else 'arm64') if cpu == 0x100000c else {
        0x1000007: 'x86_64', 7: 'i386', 12: 'arm', 0x200000c: 'arm64_32'}.get(cpu, 'cpu-' + str(cpu))
    cursor, identity = header, None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from(endian + 'II', data, cursor)
        require(size >= 8 and cursor + size <= header + sizecmds, 'Invalid load command')
        if cmd == 0x1b:
            require(size == 24 and identity is None, 'Invalid/duplicate LC_UUID')
            identity = str(uuid.UUID(bytes=data[cursor + 8:cursor + 24])).upper()
        cursor += size
    require(cursor == header + sizecmds, 'Load command size mismatch')
    return {arch: {'uuid': identity, 'sha256': digest(data), 'size': len(data),
                   'cpu_type': cpu, 'cpu_subtype': subtype}}


def describe(data):
    return {'size': len(data), 'sha256': digest(data), 'architectures': macho(data)}


def inspect_package(path):
    inventory = {}
    with zipfile.ZipFile(path) as package:
        require(len(package.namelist()) == len(set(package.namelist())), 'Duplicate ZIP member')
        prefix = 'Payload/Dopamine.app/'
        info = plistlib.loads(package.read(prefix + 'Info.plist'))
        app = package.read(prefix + 'Dopamine')
        embedded = package.read(prefix + 'libjailbreak.dylib')
        basebin = package.read(prefix + 'basebin.tar')
        for entry in package.infolist():
            if not entry.is_dir():
                data = package.read(entry)
                if data[:4] in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf',
                                b'\xbe\xba\xfe\xca', b'\xbf\xba\xfe\xca',
                                b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
                                b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce'):
                    inventory[entry.filename] = describe(data)
        components = {}
        with tarfile.open(fileobj=io.BytesIO(basebin)) as archive:
            members = {}
            for member in archive.getmembers():
                name = member.name.removeprefix('./')
                require(name not in members, 'Duplicate tar member')
                members[name] = member
                if member.isfile():
                    data = archive.extractfile(member).read()
                    if macho(data) is not None:
                        inventory['basebin.tar::' + name] = describe(data)
            for name in CORE:
                member = members['basebin/' + name]
                require(member.isfile(), 'Core component must be a regular file')
                components[name] = describe(archive.extractfile(member).read())
            version = archive.extractfile(members['basebin/.version']).read().decode().strip()
    return {'app': {'info': {k: info.get(k) for k in (
        'CFBundleIdentifier', 'CFBundleShortVersionString', 'CFBundleVersion')},
        'executable': describe(app), 'embedded_libjailbreak': describe(embedded)},
        'basebin': {'size': len(basebin), 'sha256': digest(basebin), 'version': version},
        'components': components, 'macho_inventory': inventory}


def uuid_map(record):
    arches = record['architectures']
    require(arches and all(v['uuid'] for v in arches.values()), 'Required component UUID missing')
    return {k: v['uuid'] for k, v in arches.items()}


def collect(output):
    scope = private_scope()  # Repeat the live privacy/source checks just before collection.
    require(not output.exists(), 'Output already exists; refuse overwrite')
    component_report = json.loads((ROOT / 'artifacts/d1-apple-components.json').read_text())
    require(component_report['checks_pass'] is True and component_report['sha'] == scope['final_commit'],
            'Actual Apple component checks did not pass for this SHA')
    tipa = ROOT / 'Application/Dopamine.tipa'
    contents = inspect_package(tipa)
    for name in CORE:
        actual = contents['components'][name]
        checked = component_report['components'][name]
        require(actual['sha256'] == checked['sha256'], 'Packaged component hash mismatch: ' + name)
        reported = {arch: value for value, arch in re.findall(
            r'UUID: ([0-9A-F-]+) \(([^)]+)\)', checked['uuid'])}
        require(uuid_map(actual) == reported and set(reported) == {'arm64', 'arm64e'},
                'Packaged component UUID/architecture mismatch: ' + name)
    app = contents['app']
    require(app['info'] == {k: component_report['app'][k] for k in app['info']}, 'App plist mismatch')
    require(uuid_map(app['embedded_libjailbreak']) == uuid_map(contents['components']['libjailbreak.dylib']),
            'App/basebin libjailbreak UUID mismatch')
    require(uuid_map(app['executable']) == {arch: value for value, arch in re.findall(
        r'UUID: ([0-9A-F-]+) \(([^)]+)\)', component_report['app']['uuid'])}, 'App UUID mismatch')
    with zipfile.ZipFile(tipa) as archive:
        require(scope['final_commit'].encode() in archive.read('Payload/Dopamine.app/Dopamine'),
                'App does not embed the actual final commit')
    output.mkdir(parents=True)
    name = 'Dopamine_3.0.7-' + scope['final_commit'][:7] + '_D1-single-person-research.tipa'
    shutil.copyfile(tipa, output / name)
    require((output / name).read_bytes() == tipa.read_bytes(), 'Package copy mismatch')
    for name_receipt in RECEIPTS:
        shutil.copyfile(ROOT / 'artifacts' / name_receipt, output / name_receipt)
    shutil.copyfile(ROOT / 'docs/review/candidate-status.json', output / 'candidate-status.json')
    (output / 'source-delta.patch').write_bytes(git('diff', '--binary', ANCHOR, scope['final_commit']))
    manifest = {**scope, 'classification': 'single-person-research-exception',
        'distributable': False, 'F1': 'FAIL', 'F3': 'FAIL', 'device_acceptance': False,
        'package': {'name': name, 'size': tipa.stat().st_size, 'sha256': digest(tipa.read_bytes())},
        'contents': contents,
        'receipt_sha256': {p.name: digest(p.read_bytes()) for p in sorted(output.iterdir()) if p.name != name},
        'known_limitations': [
            'Client privilege stage logging closes after App startup; manage-mounts does not reopen it.',
            'Server failure records may support partial attribution only; no complete client transaction proof.',
            'Missing logs, empty lists, no reported error, or skipped get-root do not prove success.',
            'No device installation or test is authorized by this delivery.']}
    write_json(output / 'package-manifest.json', manifest)
    print('Collected private research package:', name)


def verify(directory):
    manifest = json.loads((directory / 'package-manifest.json').read_text(encoding='utf-8'))
    package = manifest['package']
    require(Path(package['name']).name == package['name'], 'Invalid package filename')
    path = directory / package['name']
    require(path.stat().st_size == package['size'] and digest(path.read_bytes()) == package['sha256'],
            'Downloaded package hash/size mismatch')
    require(inspect_package(path) == manifest['contents'], 'Downloaded package contents mismatch')
    for name, expected in manifest['receipt_sha256'].items():
        require(Path(name).name == name and digest((directory / name).read_bytes()) == expected,
                'Receipt hash mismatch: ' + name)
    require(manifest['runtime_anchor'] == ANCHOR and manifest['repository'] == REPOSITORY
            and manifest['ref'] == REF and manifest['distributable'] is False
            and manifest['F1'] == manifest['F3'] == 'FAIL', 'Research boundary mismatch')
    result = {'package': package, 'final_commit': manifest['final_commit'], 'runtime_anchor': ANCHOR,
              'hash_size_package_contents_receipts_verified': True, 'device_acceptance': False}
    write_json(directory / 'local-verification.json', result)
    print(json.dumps(result, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--preflight', action='store_true')
    modes.add_argument('--output', type=Path)
    modes.add_argument('--verify', type=Path)
    args = parser.parse_args()
    if args.preflight:
        proof = private_scope()
        (ROOT / 'artifacts').mkdir(exist_ok=True)
        write_json(ROOT / 'artifacts/single-person-source-proof.json', proof)
        print('Approved private delivery scope and runtime source identity verified.')
    elif args.output:
        collect(args.output)
    else:
        verify(args.verify)


if __name__ == '__main__':
    main()
