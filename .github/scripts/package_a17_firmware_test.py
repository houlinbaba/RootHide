#!/usr/bin/env python3
"""Collect the explicitly approved A17 firmware test; never execute iOS code."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import zipfile

from package_single_person_research import (
    CORE, RECEIPTS, ROOT, digest, git, inspect_package, require, uuid_map, write_json,
)

BASE = '94b5c02c07fa423b06e75cd2f1e487781b038330'
RUNTIME_ANCHOR = '19de4772acad5d152023088d5edc654150f34378'
VERIFIED_UI = '0e208c0f81f8514e6ee4556daff6ebd7efbf9af4'
FIRMWARE_COMMIT = '28829475b7f00c3c881ed03602020d0907d84eac'
REPOSITORY = 'kulinichx/RootHide-Dev'
REF = 'refs/heads/codex/ios17-a17-firmware-20261020'
SOURCE_PATHS = {
    '.github/scripts/test_firmware_images.py',
    'Application/Dopamine.xcodeproj/project.pbxproj',
    'Application/Dopamine/Jailbreak/DOEnvironmentManager.h',
    'Application/Dopamine/Jailbreak/DOEnvironmentManager.m',
    'Application/Dopamine/Jailbreak/DOJailbreaker.m',
    'Application/Dopamine/Jailbreak/DOFirmwareManager.h',
    'Application/Dopamine/Jailbreak/DOFirmwareManager.m',
    'Application/Dopamine/Jailbreak/DOFirmwareValidation.h',
    'BaseBin/_external/include/partial/partial.h',
}
DELIVERY_PATHS = {
    '.github/workflows/roothide.yml',
    '.github/scripts/package_a17_firmware_test.py',
}


def delivery_scope():
    expected = {
        'GITHUB_REPOSITORY': REPOSITORY, 'GITHUB_REF': REF,
        'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_ACTOR': 'kulinichx',
        'GITHUB_TRIGGERING_ACTOR': 'kulinichx',
    }
    require(all(os.environ.get(k) == v for k, v in expected.items()),
            'A17 firmware test repository/branch/actor/manual scope rejected')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
    require(event['repository']['full_name'] == REPOSITORY
            and event['repository']['private'] is True, 'Unexpected private repository')
    require(event['repository']['default_branch'] != REF.removeprefix('refs/heads/'),
            'Test delivery must use its dedicated branch')
    inputs = event['inputs']
    require(str(inputs.get('a17_firmware_delivery', '')).lower() == 'true'
            and inputs.get('build_mode') == 'full', 'Explicit full A17 firmware test required')
    require(str(inputs.get('single_person_delivery', 'false')).lower() == 'false',
            'Delivery modes cannot be combined')
    require(str(inputs.get('ui_group_test_delivery', 'false')).lower() == 'false',
            'UI and A17 delivery modes cannot be combined')
    head = git('rev-parse', 'HEAD').decode().strip()
    require(head == os.environ['GITHUB_SHA'], 'Checkout does not match dispatched SHA')
    git('merge-base', '--is-ancestor', FIRMWARE_COMMIT, head)
    changed = set(git('diff', '--name-only', BASE, head).decode().splitlines())
    require(changed == SOURCE_PATHS | DELIVERY_PATHS, 'Unexpected A17 firmware test source delta')
    for path in sorted(SOURCE_PATHS):
        require(git('rev-parse', head + ':' + path) == git('rev-parse', FIRMWARE_COMMIT + ':' + path),
                'Verified firmware file changed: ' + path)
    trees = {}
    for label, revision in [('base', BASE), ('final', head)]:
        entries = git('ls-tree', '-rz', '--full-tree', revision).split(b'\0')
        entries = [e for e in entries if e and
                   e.split(b'\t', 1)[1].decode() not in SOURCE_PATHS | DELIVERY_PATHS]
        trees[label] = digest(b'\0'.join(entries))
    require(trees['base'] == trees['final'], 'Backend/source/submodule objects changed')
    status = json.loads((ROOT / 'docs/review/candidate-status.json').read_text())
    require(status['distributable'] is False and status['classification'] == 'compile-research'
            and status['F1'] == status['F3'] == 'FAIL', 'Unresolved findings changed')
    return {
        'runtime_anchor': RUNTIME_ANCHOR, 'source_baseline': BASE,
        'verified_ui_commit': VERIFIED_UI, 'verified_firmware_commit': FIRMWARE_COMMIT, 'final_commit': head,
        'repository': REPOSITORY, 'ref': REF, 'changed_paths': sorted(changed),
        'source_tree_excluding_firmware_and_delivery': trees,
        'run_id': os.environ['GITHUB_RUN_ID'], 'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'],
        'run_url': 'https://github.com/' + REPOSITORY + '/actions/runs/' + os.environ['GITHUB_RUN_ID'],
        'classification': 'a17-firmware-test', 'distributable': False,
        'F1': 'FAIL', 'F3': 'FAIL', 'device_acceptance': False,
        'known_limitations': [
            'A17 certificate firmware preparation and existing functions require device regression testing.',
            'F1: timeout/late server work ownership remains unresolved.',
            'F3: bounded userspace reboot handoff remains unresolved.',
            'This is an explicitly approved private A17 test, not a stable release.',
        ],
    }


def collect(output):
    scope = delivery_scope()
    require(not output.exists(), 'Output already exists; refuse overwrite')
    report = json.loads((ROOT / 'artifacts/d1-apple-components.json').read_text())
    require(report['checks_pass'] is True and report['sha'] == scope['final_commit'],
            'Actual Apple component checks did not pass for this SHA')
    tipa = ROOT / 'Application/Dopamine.tipa'
    contents = inspect_package(tipa)
    for name in CORE:
        actual, checked = contents['components'][name], report['components'][name]
        require(actual['sha256'] == checked['sha256'], 'Component hash mismatch: ' + name)
        reported = {arch: value for value, arch in re.findall(
            r'UUID: ([0-9A-F-]+) \(([^)]+)\)', checked['uuid'])}
        require(uuid_map(actual) == reported and set(reported) == {'arm64', 'arm64e'},
                'Component UUID/architecture mismatch: ' + name)
    app = contents['app']
    require(app['info'] == {k: report['app'][k] for k in app['info']}, 'App plist mismatch')
    require(uuid_map(app['embedded_libjailbreak']) ==
            uuid_map(contents['components']['libjailbreak.dylib']), 'App/basebin library mismatch')
    require(uuid_map(app['executable']) == {arch: value for value, arch in re.findall(
        r'UUID: ([0-9A-F-]+) \(([^)]+)\)', report['app']['uuid'])}, 'App UUID mismatch')
    with zipfile.ZipFile(tipa) as archive:
        require(scope['final_commit'].encode() in archive.read('Payload/Dopamine.app/Dopamine'),
                'App does not embed this final commit')
    for receipt, key in [('runtime-identity-tests.json', 'pass'),
                         ('privilege-first-failure-tests.json', 'acceptance_pass')]:
        result = json.loads((ROOT / 'artifacts' / receipt).read_text())
        require(result[key] is True, 'Regression receipt failed: ' + receipt)
    output.mkdir(parents=True)
    name = 'Dopamine_3.0.7-' + scope['final_commit'][:7] + '_A17-firmware-test.tipa'
    shutil.copyfile(tipa, output / name)
    require((output / name).read_bytes() == tipa.read_bytes(), 'Package copy mismatch')
    for receipt in RECEIPTS:
        shutil.copyfile(ROOT / 'artifacts' / receipt, output / receipt)
    shutil.copyfile(ROOT / 'docs/review/candidate-status.json', output / 'candidate-status.json')
    (output / 'source-delta.patch').write_bytes(git('diff', '--binary', BASE, scope['final_commit']))
    manifest = {**scope, 'contents': contents,
        'package': {'name': name, 'size': tipa.stat().st_size, 'sha256': digest(tipa.read_bytes())},
        'receipt_sha256': {p.name: digest(p.read_bytes()) for p in sorted(output.iterdir()) if p.name != name}}
    write_json(output / 'package-manifest.json', manifest)
    print('Collected approved A17 firmware test package:', name)


def verify(directory):
    manifest = json.loads((directory / 'package-manifest.json').read_text(encoding='utf-8'))
    require(manifest['runtime_anchor'] == RUNTIME_ANCHOR and manifest['source_baseline'] == BASE
            and manifest['verified_ui_commit'] == VERIFIED_UI and manifest['verified_firmware_commit'] == FIRMWARE_COMMIT
            and manifest['repository'] == REPOSITORY and manifest['ref'] == REF
            and manifest['classification'] == 'a17-firmware-test'
            and manifest['distributable'] is False and manifest['device_acceptance'] is False
            and manifest['F1'] == manifest['F3'] == 'FAIL', 'Group test boundary mismatch')
    package = manifest['package']
    require(package['name'] == 'Dopamine_3.0.7-' + manifest['final_commit'][:7]
            + '_A17-firmware-test.tipa', 'Unexpected package filename')
    path = directory / package['name']
    require(path.stat().st_size == package['size'] and digest(path.read_bytes()) == package['sha256'],
            'Downloaded package hash/size mismatch')
    require(inspect_package(path) == manifest['contents'], 'Downloaded package contents mismatch')
    for name, expected in manifest['receipt_sha256'].items():
        require(Path(name).name == name and digest((directory / name).read_bytes()) == expected,
                'Receipt hash mismatch: ' + name)
    result = {'package': package, 'final_commit': manifest['final_commit'],
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
        scope = delivery_scope()
        (ROOT / 'artifacts').mkdir(exist_ok=True)
        write_json(ROOT / 'artifacts/ui-group-test-source-proof.json', scope)
        print('Approved A17 firmware test scope and unchanged runtime/UI outside firmware scope verified.')
    elif args.output:
        collect(args.output)
    else:
        verify(args.verify)


if __name__ == '__main__':
    main()
