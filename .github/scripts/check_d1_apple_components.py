#!/usr/bin/env python3
"""Check linked Apple products and package contents; never execute iOS code."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import plistlib
import re
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]

def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.STDOUT)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = {'classification': 'compile-research', 'F3': 'FAIL', 'F1': 'FAIL',
              'device_acceptance': False, 'checks_pass': False, 'components': {}}
    try:
        report['sha'] = command('git', 'rev-parse', 'HEAD').strip()
        report['xcode'] = command('xcodebuild', '-version')
        report['sdk'] = command('xcrun', '--sdk', 'iphoneos', '--show-sdk-version').strip()
        assert report['sdk'] == '17.5'
        components = ['libjailbreak.dylib', 'launchdhook.dylib', 'boomerang', 'jailbreakd', 'jbctl']
        for name in components:
            path = ROOT / 'BaseBin/.build' / name
            info = report['components'][name] = {
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'archs': command('lipo', '-archs', str(path)).strip(),
                'uuid': command('dwarfdump', '--uuid', str(path)),
                'libraries': command('otool', '-L', str(path))}
            assert {'arm64','arm64e'} <= set(info['archs'].split()), name
        lib = ROOT / 'BaseBin/.build/libjailbreak.dylib'
        exports = command('nm', '-gU', str(lib))
        for symbol in ['_rh_failure_begin', '_rh_failure_note', '_rh_failure_end']:
            assert re.search(r'\b' + symbol + r'\b', exports), symbol
        assert b'privilege.first_failure operation=' in lib.read_bytes()
        server = ROOT / 'BaseBin/.build/launchdhook.dylib'
        imports = command('nm', '-u', str(server))
        assert '_rh_failure_begin' in imports and '_rh_failure_end' in imports
        assert '@loader_path/libjailbreak.dylib' in report['components']['launchdhook.dylib']['libraries']
        assert b'get_root\0' in server.read_bytes() and b'checkin_server\0' in server.read_bytes()
        app = ROOT / 'Application/build/Build/Products/Debug-iphoneos/Dopamine.app'
        app_info = plistlib.loads((app / 'Info.plist').read_bytes())
        report['app'] = {k: app_info.get(k) for k in ['CFBundleIdentifier','CFBundleShortVersionString','CFBundleVersion']}
        report['app']['uuid'] = command('dwarfdump', '--uuid', str(app / 'Dopamine'))
        report['app']['libraries'] = command('otool', '-L', str(app / 'Dopamine'))
        # For the main executable both loader_path and executable_path resolve
        # to the App directory. Check the resolved bundled dependency instead
        # of assuming a particular spelling used by a helper target's script.
        linked = re.findall(r'^\s+(\S+) \(compatibility',report['app']['libraries'],re.M)
        jailbreak_links = [name for name in linked if name.endswith('/libjailbreak.dylib')]
        assert len(jailbreak_links) == 1, jailbreak_links
        install_name = jailbreak_links[0]
        resolved = None
        for prefix in ['@loader_path/','@executable_path/']:
            if install_name.startswith(prefix):
                resolved = ((app / 'Dopamine').parent / install_name[len(prefix):]).resolve()
        assert resolved == (app / 'libjailbreak.dylib').resolve(), install_name
        report['app']['resolved_libjailbreak'] = str(resolved)
        embedded = command('dwarfdump', '--uuid', str(app / 'libjailbreak.dylib'))
        uuids = lambda value: re.findall(r'UUID: ([0-9A-F-]+) \(([^)]+)\)',value)
        assert uuids(embedded) and uuids(embedded) == uuids(report['components']['libjailbreak.dylib']['uuid'])
        assert b'privilege.first_failure operation=' in (app / 'libjailbreak.dylib').read_bytes()
        with zipfile.ZipFile(ROOT / 'Application/Dopamine.tipa') as package:
            basebin = package.read('Payload/Dopamine.app/basebin.tar')
            with tarfile.open(fileobj=io.BytesIO(basebin)) as archive:
                members = {m.name.removeprefix('./'): m for m in archive.getmembers()}
                for name in components:
                    data = archive.extractfile(members['basebin/' + name]).read()
                    assert hashlib.sha256(data).hexdigest() == report['components'][name]['sha256'], name
                report['basebin_version'] = archive.extractfile(members['basebin/.version']).read().decode().strip()
        report['checks_pass'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
