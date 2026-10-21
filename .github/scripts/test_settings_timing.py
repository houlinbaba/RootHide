#!/usr/bin/env python3
"""Exercise production timing aggregation, wrappers and ordered background export writes."""
import argparse
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from test_settings_runtime_snapshot import method

ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / 'Application/Dopamine/UI'
SETTINGS = UI / 'Settings'
CLIENT = ROOT / 'BaseBin/libjailbreak/src'

C_TEST = r'''
#include "DOSettingsTiming.h"
#include <assert.h>
#include <string.h>
int main(void) {
    struct DOSettingsTiming t = {0};
    DOSettingsTimingRecord(&t, DOSettingsTimingBackdrop, 1, 1, 1.005);
    DOSettingsTimingRecord(&t, DOSettingsTimingBackdrop, 1, 1, 1.010);
    DOSettingsTimingRecord(&t, DOSettingsTimingBackdrop, 1, 1, 1.020);
    DOSettingsTimingRecord(&t, DOSettingsTimingMaterial, 0, 1, 1.003);
    struct DOSettingsTimingSample s = t.samples[1][DOSettingsTimingBackdrop];
    assert(s.calls == 3 && s.over8ms == 2 && s.over16ms == 1);
    assert(fabs(s.total - .035) < 1e-9 && fabs(s.maximum - .020) < 1e-9);
    assert(t.samples[0][DOSettingsTimingMaterial].calls == 1);
    assert(t.samples[0][DOSettingsTimingBackdrop].calls == 0);
    struct DOSettingsTiming before = t;
    DOSettingsTimingRecord(&t, DOSettingsTimingBackdrop, 0, 0, 1);
    DOSettingsTimingRecord(&t, DOSettingsTimingBackdrop, 0, 2, 1);
    DOSettingsTimingRecord(&t, DOSettingsTimingBackdrop, 0, NAN, 1);
    DOSettingsTimingRecord(&t, DOSettingsTimingBackdrop, 0, 1, INFINITY);
    DOSettingsTimingRecord(&t, DOSettingsTimingKindCount, 0, 1, 2);
    DOSettingsTimingRecord(&t, -1, 0, 1, 2);
    DOSettingsTimingRecord(NULL, DOSettingsTimingCell, 0, 1, 2);
    assert(memcmp(&before, &t, sizeof(t)) == 0);
    assert(DOSettingsTimingNow() > 0);
    return 0;
}
'''

OBJC_TEST = r'''
#import <Foundation/Foundation.h>
#include <assert.h>
#include "DOSettingsTiming.h"
#include "roothide_stage.h"
// QUEUE
static NSString *testLogPath;
@interface DOUIManager : NSObject
+ (instancetype)sharedInstance;
- (NSString *)rootHideStageLogPath;
- (void)appendSettingsTimingReport:(NSString *)report;
@end
@implementation DOUIManager
+ (instancetype)sharedInstance { static DOUIManager *v; if (!v) v = [self new]; return v; }
- (NSString *)rootHideStageLogPath { return testLogPath; }
// APPEND
@end
@interface UITableView : NSObject
@property BOOL tracking, dragging, decelerating;
@end
@implementation UITableView @end
@interface DOCustomLiquidGlassView : NSObject
@property NSUInteger reloads;
- (void)reloadMaterial;
@end
@implementation DOCustomLiquidGlassView
- (void)reloadMaterial { self.reloads++; }
@end
@interface DOTestBase : NSObject
- (void)viewDidLayoutSubviews;
@end
@implementation DOTestBase
- (void)viewDidLayoutSubviews {}
@end
typedef NSObject UITableViewCell;
@interface DOSettingsController : DOTestBase {
@public struct DOSettingsTiming _settingsTiming;
}
@property(nonatomic, strong) UITableView *settingsTimingTable;
@property BOOL settingsTimingEnabled;
@property NSUInteger settingsTimingReports, backdropCalls, cellCalls, hairlineCalls;
@property(nonatomic, strong) DOCustomLiquidGlassView *glass;
- (BOOL)settingsTimingIsScrolling;
- (void)flushSettingsTiming;
- (void)customGlassRefreshSectionBackdrops;
- (void)customGlassRefreshSectionBackdropsContent;
- (void)reloadSettingsGlassMaterial:(DOCustomLiquidGlassView *)glass;
- (void)customGlassCleanupTableHairlines;
- (void)customGlassCleanupTableHairlinesContent;
- (void)customGlassStyleVisibleCell:(UITableViewCell *)cell atIndexPath:(NSIndexPath *)path;
- (void)customGlassStyleVisibleCellContent:(id)cell atIndexPath:(NSIndexPath *)path;
@end
@implementation DOSettingsController
- (void)customGlassRefreshSectionBackdropsContent {
    self.backdropCalls++;
    for (int i = 0; i < 3; i++) [self reloadSettingsGlassMaterial:self.glass];
}
- (void)customGlassStyleVisibleCellContent:(id)cell atIndexPath:(NSIndexPath *)path {
    (void)cell; (void)path; self.cellCalls++;
}
- (void)customGlassCleanupTableHairlinesContent { self.hairlineCalls++; }
// METHODS
@end
int main(int argc, char **argv) {
    @autoreleasepool {
        assert(argc == 2);
        testLogPath = [NSString stringWithUTF8String:argv[1]];
        DOSettingsController *c = [DOSettingsController new];
        c.settingsTimingTable = [UITableView new];
        c.glass = [DOCustomLiquidGlassView new];
        [c customGlassRefreshSectionBackdrops];
        assert(c.backdropCalls == 1 && c.glass.reloads == 3);
        assert(c->_settingsTiming.samples[0][DOSettingsTimingBackdrop].calls == 0);
        c.settingsTimingEnabled = YES;
        c.settingsTimingTable.tracking = YES;
        [c customGlassRefreshSectionBackdrops];
        [c customGlassStyleVisibleCell:nil atIndexPath:nil];
        [c viewDidLayoutSubviews];
        assert(c->_settingsTiming.samples[1][DOSettingsTimingBackdrop].calls == 2);
        assert(c->_settingsTiming.samples[1][DOSettingsTimingMaterial].calls == 6);
        assert(c->_settingsTiming.samples[1][DOSettingsTimingCell].calls == 1);
        assert(c->_settingsTiming.samples[1][DOSettingsTimingHairlines].calls == 1);
        assert(c->_settingsTiming.samples[1][DOSettingsTimingLayout].calls == 1);
        c.settingsTimingTable.tracking = NO;
        c.settingsTimingTable.decelerating = YES;
        assert([c settingsTimingIsScrolling]);
        c.settingsTimingTable.decelerating = NO;
        c.settingsTimingTable.dragging = YES;
        assert([c settingsTimingIsScrolling]);
        c.settingsTimingTable.dragging = NO;
        [c customGlassRefreshSectionBackdrops];
        assert(c->_settingsTiming.samples[0][DOSettingsTimingBackdrop].calls == 1);
        [c flushSettingsTiming];
        assert(c.settingsTimingReports == 1 && c->_settingsTiming.samples[1][DOSettingsTimingCell].calls == 0);
        // The actual export queue must read a preceding asynchronous write.
        dispatch_sync(DOFileDiagnosticsQueue(), ^{
            NSString *log = [NSString stringWithContentsOfFile:testLogPath encoding:NSUTF8StringEncoding error:nil];
            assert([log containsString:@"scroll material n=6"] && [log containsString:@"idle backdrop n=1"]);
            assert([log containsString:@"fps_measured=0"] && log.length < 2048);
        });
        [c flushSettingsTiming];
        assert(c.settingsTimingReports == 1); // Empty summaries are omitted.
        for (int i = 0; i < 30; i++) {
            [c customGlassStyleVisibleCell:nil atIndexPath:nil];
            [c flushSettingsTiming];
        }
        assert(c.settingsTimingReports == 16);
        dispatch_sync(DOFileDiagnosticsQueue(), ^{});
        c.settingsTimingEnabled = NO;
        [c flushSettingsTiming];
        assert(c.settingsTimingReports == 16);
        puts("PASS: production timing wrappers, mode split, inclusive counts, reset, report cap and FIFO file/export queue");
    }
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args()
    controller = (SETTINGS / 'DOSettingsController.m').read_text(encoding='utf-8')
    manager = (UI / 'DOUIManager.m').read_text(encoding='utf-8')
    timing_names = ('- (BOOL)settingsTimingIsScrolling', '- (void)flushSettingsTiming',
                    '- (void)customGlassRefreshSectionBackdrops\n',
                    '- (void)reloadSettingsGlassMaterial:',
                    '- (void)customGlassStyleVisibleCell:',
                    '- (void)customGlassCleanupTableHairlines\n',
                    '- (void)viewDidLayoutSubviews')
    production = '\n'.join(method(controller[controller.index('@implementation DOSettingsController'):], s)
                           for s in timing_names)
    for body in (method(controller, '- (void)customGlassRefreshSectionBackdrops\n'),
                 method(controller, '- (void)customGlassStyleVisibleCell:'),
                 method(controller, '- (void)reloadSettingsGlassMaterial:')):
        assert 'DOSettingsTimingRecord' in body
        for forbidden in ('dispatch_', 'appendSettingsTimingReport', 'file_log', 'flushSettingsTiming'):
            assert forbidden not in body
    assert method(controller, '- (void)shareRootHideStageLogPressed').index('flushSettingsTiming') < method(controller, '- (void)shareRootHideStageLogPressed').index('shareRootHideStageLogFromView:')
    assert 'settingsTimingEnabled = NO' in method(controller, '- (void)viewWillDisappear:')
    if args.check_only:
        print('PASS: memory-only measured callbacks, bounded summaries and pre-export flush wiring; runtime tests not run')
        return
    if args.workdir:
        args.workdir.mkdir(parents=True, exist_ok=False)
    context = nullcontext(args.workdir) if args.workdir else tempfile.TemporaryDirectory(prefix='settings-timing-')
    with context as directory:
        temp = Path(directory)
        cfile, binary = temp / 'test.c', temp / ('test.exe' if sys.platform == 'win32' else 'test')
        cfile.write_text(C_TEST, encoding='utf-8')
        compiler = [str(args.zig), 'cc'] if args.zig else ['xcrun', 'clang']
        subprocess.run(compiler + ['-std=c11', '-D_POSIX_C_SOURCE=200809L', '-Wall', '-Wextra', '-Werror',
            '-I', str(SETTINGS), str(cfile), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=10)
        print('PASS: production timing aggregation, thresholds, isolation and invalid samples', flush=True)
        if sys.platform != 'darwin':
            print('Foundation/UIKit runtime not run on this host; Apple CI required.')
            return
        queue = method(manager, 'static dispatch_queue_t DOFileDiagnosticsQueue(void)')
        append = method(manager, '- (void)appendSettingsTimingReport:')
        harness = OBJC_TEST.replace('// QUEUE', queue).replace('// APPEND', append).replace('// METHODS', production)
        mfile = temp / 'test.m'
        mfile.write_text(harness, encoding='utf-8')
        stage_object = temp / 'stage.o'
        subprocess.run(['xcrun', 'clang', '-D_DARWIN_C_SOURCE', '-Wall', '-Wextra', '-Werror',
            '-fsanitize=address,undefined', '-c', str(CLIENT / 'roothide_stage.c'),
            '-o', str(stage_object)], check=True)
        subprocess.run(['xcrun', 'clang', '-fobjc-arc', '-fblocks', '-D_DARWIN_C_SOURCE',
            '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', '-framework', 'Foundation',
            '-I', str(SETTINGS), '-I', str(CLIENT), str(mfile), str(stage_object),
            '-o', str(binary)], check=True)
        subprocess.run([str(binary), str(temp / 'stage.log')], check=True, timeout=20)
    (ROOT / 'artifacts').mkdir(exist_ok=True)
    files = ['Settings/DOSettingsController.m', 'Settings/DOSettingsTiming.h', 'DOUIManager.m', 'DOUIManager.h']
    receipt = {'pass': True, 'uikit_runtime': False, 'device_scrolling_measured': False,
               'source_sha256': {p: hashlib.sha256((UI / p).read_bytes()).hexdigest() for p in files}}
    (ROOT / 'artifacts/settings-timing-tests.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
