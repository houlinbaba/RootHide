#!/usr/bin/env python3
"""Collect the approved public settings/terminal diagnostics test; never execute iOS code."""
import argparse
import io
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import zipfile

from package_single_person_research import (
    CORE, RECEIPTS, ROOT, digest, git, inspect_package, require, uuid_map, write_json,
)

RECEIPTS = (*RECEIPTS, 'settings-scroll-tests.json', 'settings-timing-tests.json', 'terminal-diagnostics-tests.json')
BASE = 'c5380e3da4a365a8669545f0217bab02d928ca99'
RUNTIME_ANCHOR = BASE
VERIFIED_UI = 'ad13a957b4ab3b6bb1fd1b6922bf1f98a1dd7eac'
VERIFIED_TESTS = VERIFIED_UI
VERIFIED_HARNESS = 'ca36ec6690530fd83405e671bcbf6296b08ea436'
VERIFIED_TERMINAL_BASE = '6cef532e683637892e59746a15e6a352527c7813'
# Exact diagnostic blobs are pinned below; the rest of the runtime and all
# submodules must still match the firmware baseline. No floating source pin.
TERMINAL_SOURCE_SHA256 = {
    ".github/scripts/test_runtime_identity.py": "5c087bf70c6dcb21e382788da5a77a719e3696697db65e67a4eee9206c611da4",
    ".github/scripts/test_terminal_diagnostics.py": "de1b59b3247aff448d24e028818abf6342adae866353574b4eb8172131dccdcd",
    ".github/scripts/test_roothide_diagnostic_export.py": "e2f2e854a80c9dd1c742b57d9df87ed8d90bb60fa8b16515f515a37df85638e3",
    "Application/Dopamine/UI/DOUIManager.m": "02a53d8b5c84e7e3e622de25fef459cd2ecef214e3892ca0ba786332105d0974",
    "Application/Dopamine/UI/DODiagnosticLogQuery.h": "f9e871ec1107a14aee2843808e17e62bb5f5439419a675df3df4aadf5402e91e",
    "BaseBin/launchdhook/src/jbserver/jbdomain_dopamine.c": "fc9af7d3304b8c3e7cbfd09733346a7f669cc7b211965d299411fdf2b6e723f9",
    "BaseBin/libjailbreak/src/jbclient_xpc.c": "365c2677a824c83c1220f879fbc8d7cb6b785e2516429521961c1f7243d6a025",
    "BaseBin/libjailbreak/src/jbclient_xpc.h": "3644eb8e75e2138799d7276dc514838a51eaa7a88afd708000de67c6384eeee0",
    "BaseBin/libjailbreak/src/jbserver_domains.h": "39587d38c0aa35fc6bc115e017d9b4d30043ff7004ac57038511b1411fbd31c9",
    "BaseBin/libjailbreak/src/diagnostic_log.h": "9762deb53b4a032303aba52219a5d0ba91ad031026d23f23c7f5e409e2edf503",
    "BaseBin/systemhook/Makefile": "724cb311031ac595f524df4b6b417f1ce2fc964becf7e0a2da4d3481ab7f46ea",
    "BaseBin/systemhook/src/common/runtime_diagnostics.c": "71351cc8212a1f06ace32de327ad3dba6711a4b94ff30cd8859cf5befdd6936e",
    "BaseBin/systemhook/src/common/runtime_diagnostics.h": "1e0ee6ec98beb071ec19ea123f3d3ca7aea0412daf1863fb7c86c416d785fed0",
    "BaseBin/systemhook/src/main.c": "8ab1055c99ccd2471182c28cea93f11d5a963079a2b1a2b4b02026cd1b597dd0",
    "BaseBin/systemhook/src/roothider_main.c": "e37c8064605be3b958000b4b51ea791b9dd67a82d60548bf35b6994390eb14ae"
}
TERMINAL_PATHS = set(TERMINAL_SOURCE_SHA256)
FIRMWARE_COMMIT = '28829475b7f00c3c881ed03602020d0907d84eac'
REPOSITORY = 'kulinichx/RootHide'
REF = 'refs/heads/codex/settings-diagnostics-public-20261021'
SOURCE_PATHS = {
    'Application/Dopamine/UI/DOMainViewController.m',
    'Application/Dopamine/UI/Settings/DOSettingsController.m',
    'Application/Dopamine/UI/Settings/DOSettingsTiming.h',
    'Application/Dopamine/UI/DORootHideDiagnostics.h',
    'Application/Dopamine/UI/DOUIManager.h',
    'Application/Dopamine/UI/DOUIManager.m',
    '.github/scripts/test_runtime_identity.py',
    '.github/scripts/test_settings_runtime_snapshot.py',
    '.github/scripts/test_settings_timing.py',
    '.github/scripts/test_roothide_diagnostic_export.py',
}
DELIVERY_PATHS = {
    '.github/workflows/roothide.yml',
    '.github/scripts/package_settings_scroll_test.py',
}
HARNESS_PATHS = {'.github/scripts/test_boomerang_sender.py'}


def delivery_scope():
    expected = {
        'GITHUB_REPOSITORY': REPOSITORY, 'GITHUB_REF': REF,
        'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_ACTOR': 'kulinichx',
        'GITHUB_TRIGGERING_ACTOR': 'kulinichx',
    }
    require(all(os.environ.get(k) == v for k, v in expected.items()),
            'settings scroll test repository/branch/actor/manual scope rejected')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
    require(event['repository']['full_name'] == REPOSITORY
            and event['repository']['private'] is False, 'Unexpected public repository')
    require(event['repository']['default_branch'] != REF.removeprefix('refs/heads/'),
            'Test delivery must use its dedicated branch')
    inputs = event['inputs']
    require(str(inputs.get('settings_scroll_delivery', '')).lower() == 'true'
            and inputs.get('build_mode') == 'full', 'Explicit full settings scroll test required')
    require(str(inputs.get('single_person_delivery', 'false')).lower() == 'false',
            'Delivery modes cannot be combined')
    require(str(inputs.get('a17_firmware_delivery', 'false')).lower() == 'false',
            'Settings and firmware delivery modes cannot be combined')
    require(str(inputs.get('ui_group_test_delivery', 'false')).lower() == 'false',
            'Settings and UI delivery modes cannot be combined')
    head = git('rev-parse', 'HEAD').decode().strip()
    require(head == os.environ['GITHUB_SHA'], 'Checkout does not match dispatched SHA')
    git('merge-base', '--is-ancestor', VERIFIED_UI, head)
    git('merge-base', '--is-ancestor', VERIFIED_TESTS, head)
    git('merge-base', '--is-ancestor', VERIFIED_HARNESS, head)
    git('merge-base', '--is-ancestor', VERIFIED_TERMINAL_BASE, head)
    changed = set(git('diff', '--name-only', BASE, head).decode().splitlines())
    require(changed == SOURCE_PATHS | TERMINAL_PATHS | HARNESS_PATHS | DELIVERY_PATHS,
            'Unexpected settings scroll test source delta')
    for path in sorted(SOURCE_PATHS | TERMINAL_PATHS | HARNESS_PATHS):
        if path in TERMINAL_PATHS:
            require(digest(git('show', head + ':' + path)) == TERMINAL_SOURCE_SHA256[path],
                    'Pinned terminal diagnostic source changed: ' + path)
            continue
        reference = VERIFIED_HARNESS if path in HARNESS_PATHS else (
            VERIFIED_TESTS if path.endswith('.py') else VERIFIED_UI)
        require(git('rev-parse', head + ':' + path) == git('rev-parse', reference + ':' + path),
                'Verified settings file changed: ' + path)
    trees = {}
    for label, revision in [('base', BASE), ('final', head)]:
        entries = git('ls-tree', '-rz', '--full-tree', revision).split(b'\0')
        entries = [e for e in entries if e and
                   e.split(b'\t', 1)[1].decode() not in SOURCE_PATHS | TERMINAL_PATHS | HARNESS_PATHS | DELIVERY_PATHS]
        trees[label] = digest(b'\0'.join(entries))
    require(trees['base'] == trees['final'], 'Objects outside pinned diagnostics/delivery changed')
    status = json.loads((ROOT / 'docs/review/candidate-status.json').read_text())
    require(status['distributable'] is False and status['classification'] == 'compile-research'
            and status['F1'] == status['F3'] == 'FAIL', 'Unresolved findings changed')
    return {
        'runtime_anchor': RUNTIME_ANCHOR, 'source_baseline': BASE,
        'verified_ui_commit': VERIFIED_UI, 'verified_tests_commit': VERIFIED_TESTS,
        'verified_harness_commit': VERIFIED_HARNESS,
        'terminal_diagnostic_base': VERIFIED_TERMINAL_BASE,
        'terminal_diagnostic_source_sha256': TERMINAL_SOURCE_SHA256,
        'verified_firmware_commit': FIRMWARE_COMMIT, 'final_commit': head,
        'repository': REPOSITORY, 'ref': REF, 'changed_paths': sorted(changed),
        'source_tree_excluding_pinned_diagnostics_and_delivery': trees,
        'run_id': os.environ['GITHUB_RUN_ID'], 'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'],
        'run_url': 'https://github.com/' + REPOSITORY + '/actions/runs/' + os.environ['GITHUB_RUN_ID'],
        'classification': 'terminal-session-diagnostics-test', 'distributable': False,
        'F1': 'FAIL', 'F3': 'FAIL', 'device_acceptance': False,
        'known_limitations': [
            'Bounded terminal startup/spawn/exec tracing and fixed read-only log descriptors only; no terminal fix is claimed. Firmware and runtime outside the pinned diagnostic paths match c5380e3.',
            'Terminal logging is best effort. No child exit-status hook is installed; successful spawn does not establish a working terminal session.',
            'Five-second App timeout abandons late results but cannot cancel synchronous service work. One outstanding diagnostic worker is retained until return.',
            'Timing reports elapsed main-thread work in overlapping categories, not FPS or GPU time. Terminal EOF may produce no crash report.',
            'F1: timeout/late server work ownership remains unresolved.',
            'F3: bounded userspace reboot handoff remains unresolved.',
            'This public diagnostics candidate is approved for feedback testing only; stable release acceptance remains unresolved.',
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
        with tarfile.open(fileobj=io.BytesIO(archive.read('Payload/Dopamine.app/basebin.tar'))) as basebin:
            members = {m.name.removeprefix('./'): m for m in basebin.getmembers()}
            trace = basebin.extractfile(members['basebin/systemhook.dylib']).read()
            require(b'terminal=%s event=%s target=%s' in trace,
                    'Terminal diagnostic build flag was not enabled')
    for receipt, key in [('runtime-identity-tests.json', 'pass'),
                         ('privilege-first-failure-tests.json', 'acceptance_pass')]:
        result = json.loads((ROOT / 'artifacts' / receipt).read_text())
        require(result[key] is True, 'Regression receipt failed: ' + receipt)
    settings = json.loads((ROOT / 'artifacts/settings-scroll-tests.json').read_text())
    require(settings['pass'] is True and settings['controller_sha256'] ==
            digest((ROOT / 'Application/Dopamine/UI/Settings/DOSettingsController.m').read_bytes()),
            'Settings regression receipt does not match source')
    timing = json.loads((ROOT / 'artifacts/settings-timing-tests.json').read_text())
    require(timing['pass'] is True and timing['device_scrolling_measured'] is False,
            'Settings timing regression receipt did not pass')
    expected_timing_sources = {'Settings/DOSettingsController.m', 'Settings/DOSettingsTiming.h',
                               'DOUIManager.m', 'DOUIManager.h'}
    require(set(timing['source_sha256']) == expected_timing_sources,
            'Timing receipt source list mismatch')
    for path, expected in timing['source_sha256'].items():
        require(digest((ROOT / 'Application/Dopamine/UI' / path).read_bytes()) == expected,
                'Timing receipt does not match source: ' + path)
    terminal = json.loads((ROOT / 'artifacts/terminal-diagnostics-tests.json').read_text())
    require(terminal['pass'] is True and terminal['device_terminal_verified'] is False,
            'Terminal diagnostic regression receipt did not pass')
    require(terminal['source_sha256'] == TERMINAL_SOURCE_SHA256,
            'Terminal diagnostic test source list or hashes differ from the pinned sources')
    for path, expected in terminal['source_sha256'].items():
        require(digest((ROOT / path).read_bytes()) == expected,
                'Terminal diagnostic receipt does not match source: ' + path)
    output.mkdir(parents=True)
    name = 'Dopamine_3.0.7-' + scope['final_commit'][:7] + '_Terminal-session-diagnostics-test.tipa'
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
    print('Collected approved settings diagnostics test package:', name)


def verify(directory):
    manifest = json.loads((directory / 'package-manifest.json').read_text(encoding='utf-8'))
    require(manifest['runtime_anchor'] == RUNTIME_ANCHOR and manifest['source_baseline'] == BASE
            and manifest['verified_ui_commit'] == VERIFIED_UI and manifest['verified_tests_commit'] == VERIFIED_TESTS
            and manifest['verified_harness_commit'] == VERIFIED_HARNESS
            and manifest['terminal_diagnostic_base'] == VERIFIED_TERMINAL_BASE
            and manifest['terminal_diagnostic_source_sha256'] == TERMINAL_SOURCE_SHA256
            and manifest['verified_firmware_commit'] == FIRMWARE_COMMIT
            and manifest['repository'] == REPOSITORY and manifest['ref'] == REF
            and manifest['classification'] == 'terminal-session-diagnostics-test'
            and manifest['distributable'] is False and manifest['device_acceptance'] is False
            and manifest['F1'] == manifest['F3'] == 'FAIL', 'Group test boundary mismatch')
    package = manifest['package']
    require(package['name'] == 'Dopamine_3.0.7-' + manifest['final_commit'][:7]
            + '_Terminal-session-diagnostics-test.tipa', 'Unexpected package filename')
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
        write_json(ROOT / 'artifacts/settings-scroll-source-proof.json', scope)
        print('Approved terminal diagnostics source pins and unchanged firmware/runtime outside pinned diagnostics verified.')
    elif args.output:
        collect(args.output)
    else:
        verify(args.verify)


if __name__ == '__main__':
    main()
