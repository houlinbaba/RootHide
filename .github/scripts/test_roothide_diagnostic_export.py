#!/usr/bin/env python3
"""Exercise the App's file-only diagnostic collector on macOS Foundation."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / 'Application/Dopamine/UI'

HARNESS = r'''
#import "DORootHideDiagnostics.h"
#include <assert.h>
#include <utime.h>

static void save(NSString *path, NSString *text, time_t mtime) {
    assert([text writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil]);
    struct utimbuf times = {mtime, mtime};
    assert(utime(path.fileSystemRepresentation, &times) == 0);
}

int main(int argc, char **argv) {
    @autoreleasepool {
        assert(argc == 2);
        NSString *base = [NSString stringWithUTF8String:argv[1]];
        NSString *crashes = [base stringByAppendingPathComponent:@"crashes"];
        NSString *retired = [base stringByAppendingPathComponent:@"retired"];
        NSString *root = [base stringByAppendingPathComponent:@"root"];
        NSString *app = [root stringByAppendingPathComponent:@"Applications/RootHide.app"];
        for (NSString *directory in @[crashes, retired, app, [root stringByAppendingPathComponent:@"usr/lib"]]) {
            assert([[NSFileManager defaultManager] createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:nil]);
        }
        NSString *lib = [root stringByAppendingPathComponent:@"usr/lib/libroothide.dylib"];
        NSString *link = [app stringByAppendingPathComponent:@".jbroot"];
        save(lib, @"library-placeholder", 1000000);
        assert(symlink(root.fileSystemRepresentation, link.fileSystemRepresentation) == 0);
        NSString *missingStage = [base stringByAppendingPathComponent:@"missing-stage.log"];
        NSString *initLog = [base stringByAppendingPathComponent:@"init.log"];
        NSMutableString *large = [NSMutableString stringWithString:@"OLD_LOG_BYTES"];
        while (large.length < 300000) [large appendString:@"x"];
        [large appendString:@"\nINIT_DLOPEN_ERROR\n"];
        save(initLog, large, 1000000);
        save([crashes stringByAppendingPathComponent:@"Sileo-old.ips"], @"OLDEST_OMITTED", 999900);
        save([crashes stringByAppendingPathComponent:@"Sileo-new.ips"], @"SILEO_SELECTED", 999990);
        save([retired stringByAppendingPathComponent:@"Sileo-newest.ips"], @"SILEO_RETIRED_SELECTED", 1000000);
        save([crashes stringByAppendingPathComponent:@"RootHide-new.ips"], @"ROOTHIDE_SELECTED", 999999);
        save([crashes stringByAppendingPathComponent:@"RootHide-ancient.ips"], @"ANCIENT_OMITTED", 1000000 - 8 * 86400);
        save([crashes stringByAppendingPathComponent:@"RootHide-future.ips"], @"FUTURE_OMITTED", 1000600);
        save([crashes stringByAppendingPathComponent:@"OtherApp-new.ips"], @"PRIVATE_OTHER_APP", 1000000);
        save([crashes stringByAppendingPathComponent:@"RootHideHelper-new.ips"], @"PRIVATE_LOOKALIKE", 1000000);
        save([crashes stringByAppendingPathComponent:@"RootHide-new.txt"], @"NOT_CRASH", 1000000);
        NSString *report = DORootHideDiagnosticReport(@"test-version", @[missingStage, initLog], @[crashes, retired], root, [NSDate dateWithTimeIntervalSince1970:1000000]);
        assert([report containsString:@"INIT_DLOPEN_ERROR"] && [report containsString:@"truncated:"]);
        assert(![report containsString:@"OLD_LOG_BYTES"]);
        assert([report containsString:@"SILEO_SELECTED"] && [report containsString:@"SILEO_RETIRED_SELECTED"]);
        assert([report containsString:@"ROOTHIDE_SELECTED"]);
        assert([report containsString:@"unreadable (errno="] && [report containsString:@"link="]);
        assert([report containsString:[link stringByAppendingPathComponent:@"usr/lib/libroothide.dylib"]]);
        for (NSString *secret in @[@"OLDEST_OMITTED", @"ANCIENT_OMITTED", @"FUTURE_OMITTED", @"PRIVATE_OTHER_APP", @"PRIVATE_LOOKALIKE", @"NOT_CRASH"]) {
            assert(![report containsString:secret]);
        }
        assert(report.length < 270000);

        // Refuse symlinks and special files instead of following/blocking on them.
        NSString *symlinkLog = [base stringByAppendingPathComponent:@"symlink.log"];
        assert(symlink(initLog.fileSystemRepresentation, symlinkLog.fileSystemRepresentation) == 0);
        NSString *fifo = [base stringByAppendingPathComponent:@"fifo.log"];
        assert(mkfifo(fifo.fileSystemRepresentation, 0600) == 0);
        NSString *status = nil;
        assert(!DODiagnosticRead(symlinkLog, 256, YES, &status));
        assert(!DODiagnosticRead(fifo, 256, YES, &status));

        // Oversized crashes must be explicitly omitted, never shared as partial JSON.
        NSString *huge = [@"CRASH_PARTIAL_MUST_NOT_LEAK" stringByPaddingToLength:1024 * 1024 + 1 withString:@"z" startingAtIndex:0];
        save([retired stringByAppendingPathComponent:@"RootHide-huge.ips"], huge, 1000000);
        NSString *limited = DORootHideDiagnosticReport(@"test", @[], @[crashes, retired], nil, [NSDate dateWithTimeIntervalSince1970:1000000]);
        assert([limited containsString:@"exceeds 1048576-byte crash limit"]);
        assert(![limited containsString:@"CRASH_PARTIAL_MUST_NOT_LEAK"]);
        assert([limited containsString:@"ROOTHIDE_SELECTED"] && [limited containsString:@"No cached jailbreak root"]);

        // A missing stage and unreadable crash directory still yield a useful export.
        NSString *empty = DORootHideDiagnosticReport(@"test", @[missingStage], @[missingStage], nil, [NSDate dateWithTimeIntervalSince1970:1000000]);
        assert([empty containsString:@"Crash directory"] && [empty containsString:@"No recent readable sileo .ips"]);
        assert([empty containsString:@"Missing/unreadable files are not proof of success"]);
        assert([[NSFileManager defaultManager] removeItemAtPath:link error:nil]);
        assert(symlink("/missing-jailbreak-root", link.fileSystemRepresentation) == 0);
        NSMutableString *broken = [NSMutableString string];
        DOAppendDiagnosticPath(broken, link);
        assert([broken containsString:@"link=/missing-jailbreak-root"] && [broken containsString:@"realpath failed"]);
        puts("PASS: empty-stage export, recent target crashes, cross-directory newest selection, size bounds, read errors, symlink/FIFO rejection, loader links");
    }
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    source = (UI / 'DOUIManager.m').read_text(encoding='utf-8')
    export = source.split('- (void)shareRootHideStageLogFromView:', 1)[1].split('- (void)shareLogRecordFromView:', 1)[0]
    assert 'Dopamine-systemhook-init.log' in export
    assert export.index('dispatch_get_global_queue') < export.index('DORootHideDiagnosticReport(')
    assert 'dispatch_get_main_queue' in export and 'completionWithItemsHandler' in export
    assert 'fileURLWithPath:path' in export and '_rootHideExportInProgress' in export
    for forbidden in ('runAsRoot', 'runUnsandboxed', 'isJailbroken', 'jailbrokenVersion', 'HealthReport', 'jbclient_'):
        assert forbidden not in export, f'export must not wait for services: {forbidden}'
    assert 'test_roothide_diagnostic_export.py' in (ROOT / '.github/workflows/roothide.yml').read_text(encoding='utf-8')
    for language in ('en', 'zh-Hans'):
        assert '"RootHide_Log_Export_Failed"' in (ROOT / f'Application/Dopamine/{language}.lproj/Localizable.strings').read_text(encoding='utf-8')
    print('PASS: background file collection, main-thread share, service-free export wiring', flush=True)
    if args.check_only:
        print('Foundation harness NOT run (--check-only); Apple compilation and device export remain unverified.')
        return
    if sys.platform != 'darwin':
        raise SystemExit('Foundation harness requires macOS. Use --check-only for source wiring checks elsewhere.')
    with tempfile.TemporaryDirectory(prefix='roothide-export-') as directory:
        temp = Path(directory)
        harness = temp / 'test.m'
        harness.write_text(HARNESS, encoding='utf-8')
        binary = temp / 'test'
        subprocess.run(['xcrun', 'clang', '-fobjc-arc', '-fblocks', '-D_DARWIN_C_SOURCE', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-framework', 'Foundation', '-I', str(UI), str(harness), '-o', str(binary)], check=True)
        subprocess.run([str(binary), str(temp)], check=True, timeout=30,
                       env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0', 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    main()
