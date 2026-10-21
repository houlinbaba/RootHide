//
//  DOUIManager.m
//  Dopamine
//
//  Created by tomt000 on 24/01/2024.
//

#import "DOUIManager.h"
#import "DORootHideDiagnostics.h"
#import "DORuntimeIdentityQuery.h"
#import <libjailbreak/info.h>
#import <libjailbreak/roothide_stage.h>
#import "DOEnvironmentManager.h"
#import "DOThemeManager.h"
#import "DOTheme.h"
#import "NSString+Version.h"
#import <pthread.h>
#import <sys/utsname.h>

// Timing writes and exports share a serial utility queue: an export includes
// the summary just submitted by Settings without blocking its main thread.
static dispatch_queue_t DOFileDiagnosticsQueue(void)
{
    static dispatch_queue_t queue;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        dispatch_queue_attr_t attributes = dispatch_queue_attr_make_with_qos_class(
            DISPATCH_QUEUE_SERIAL, QOS_CLASS_UTILITY, 0);
        queue = dispatch_queue_create("com.opa334.Dopamine.fileDiagnostics", attributes);
    });
    return queue;
}

@implementation DOUIManager

+ (instancetype)sharedInstance
{
    static DOUIManager *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[DOUIManager alloc] init];
    });
    return sharedInstance;
}

- (id)init
{
    if (self = [super init]){
        _bootlogoPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/bootlogo.png"];
        _preferenceManager = [DOPreferenceManager sharedManager];
        _logRecord = [NSMutableArray new];
        _logLock = [NSLock new];
    }
    return self;
}

- (BOOL)isUpdateAvailable
{
    BOOL disableUpdate = [_preferenceManager boolPreferenceValueForKey:@"disableUpdateEnabled" fallback:YES];
    if (disableUpdate)
        return NO;
    
    NSArray *releases = [self getLatestReleases];
    if (releases.count == 0)
        return NO;

    
    NSString *latestVersion = [self getLatestReleaseTag];
    NSString *currentVersion = [self getLaunchedReleaseTag];
    return [latestVersion numericalVersionRepresentation] > [currentVersion numericalVersionRepresentation];
}

- (NSArray *)getUpdatesInRange:(NSString *)start end:(NSString *)end
{
    NSArray *releases = [self getLatestReleases];
    if (releases.count == 0)
        return @[];

    long long startVersion = [start numericalVersionRepresentation];
    long long endVersion = [end numericalVersionRepresentation];
    NSMutableArray *updates = [NSMutableArray new];
    for (NSDictionary *release in releases) {
        NSString *version = release[@"tag_name"];
        NSNumber *prerelease = release[@"prerelease"];
        if ([prerelease boolValue]) {
            // Skip prereleases
            continue;
        }
        long long numericalVersion = [version numericalVersionRepresentation];
        if (numericalVersion > startVersion && numericalVersion <= endVersion) {
            [updates addObject:release];
        }
    }
    return updates;
}

- (NSArray *)getLatestReleases
{
    static dispatch_once_t onceToken;
    static NSArray *releases;
    dispatch_once(&onceToken, ^{
        NSURL *url = [NSURL URLWithString:@"https://api.github.com/repos/kulinichx/RootHide/releases"];
        NSData *data = [NSData dataWithContentsOfURL:url];
        if (data) {
            NSError *error;
            releases = [NSJSONSerialization JSONObjectWithData:data options:kNilOptions error:&error];
            if (error)
            {
                onceToken = 0;
                releases = @[];
            }
        }
    });
    return releases;
}

- (BOOL)environmentUpdateAvailable
{
    if (![[DOEnvironmentManager sharedManager] jailbrokenVersion])
        return NO;

    NSString *jailbrokenVersion = [[DOEnvironmentManager sharedManager] jailbrokenVersion];
    NSString *launchedVersion = [self getLaunchedReleaseTag];
    
    return [launchedVersion numericalVersionRepresentation] > [jailbrokenVersion numericalVersionRepresentation];
}

- (bool)launchedReleaseNeedsManualUpdate
{
    NSString *launchedTag = [self getLaunchedReleaseTag];
    NSDictionary *launchedVersion;
    for (NSDictionary *release in [self getLatestReleases]) {
        if ([release[@"tag_name"] isEqualToString:launchedTag]) {
            launchedVersion = release;
            break;
        }
    }
    if (!launchedVersion)
        return false;
    return [launchedVersion[@"body"] containsString:@"*Manual Updates*"];
}

- (NSString*)getLatestReleaseTag
{
    NSArray *releases = [self getLatestReleases];
    for (NSDictionary *release in releases) {
        NSNumber *prerelease = release[@"prerelease"];
        if ([prerelease boolValue]) {
            continue;
        }
        return release[@"tag_name"];
    }
    return nil;
}

- (NSString*)getLaunchedReleaseTag
{
    return [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
}

- (NSArray*)availablePackageManagers
{
    NSString *path = [[NSBundle mainBundle] pathForResource:@"PkgManagers" ofType:@"plist"];
    return [NSArray arrayWithContentsOfFile:path];
}

- (NSArray*)enabledPackageManagerKeys
{
    NSArray *enabledPkgManagers = [_preferenceManager preferenceValueForKey:@"enabledPkgManagers"] ?: @[];
    NSMutableArray *enabledKeys = [NSMutableArray new];
    NSArray *availablePkgManagers = [self availablePackageManagers];

    [availablePkgManagers enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSString *key = obj[@"Key"];
        if ([enabledPkgManagers containsObject:key]) {
            [enabledKeys addObject:key];
        }
    }];

    return enabledKeys;
}

- (NSArray*)enabledPackageManagers
{
    NSMutableArray *enabledPkgManagers = [NSMutableArray new];
    NSArray *enabledKeys = [self enabledPackageManagerKeys];

    [[self availablePackageManagers] enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSString *key = obj[@"Key"];
        if ([enabledKeys containsObject:key]) {
            [enabledPkgManagers addObject:obj];
        }
    }];

    return enabledPkgManagers;
}

- (void)resetPackageManagers
{
    [_preferenceManager removePreferenceValueForKey:@"enabledPkgManagers"];
}

- (void)resetSettings
{
    [_preferenceManager removePreferenceValueForKey:@"verboseLogsEnabled"];
    [_preferenceManager removePreferenceValueForKey:@"tweakInjectionEnabled"];
    [self resetPackageManagers];
}

- (void)setPackageManager:(NSString*)key enabled:(BOOL)enabled
{
    NSMutableArray *pkgManagers = [self enabledPackageManagerKeys].mutableCopy;
    
    if (enabled && ![pkgManagers containsObject:key]) {
        [pkgManagers addObject:key];
    }
    else if (!enabled && [pkgManagers containsObject:key]) {
        [pkgManagers removeObject:key];
    }

    [_preferenceManager setPreferenceValue:pkgManagers forKey:@"enabledPkgManagers"];
}

- (BOOL)isDebug
{
    NSNumber *debug = [_preferenceManager preferenceValueForKey:@"verboseLogsEnabled"];
    return debug == nil ? NO : [debug boolValue];
}

- (BOOL)enableTweaks
{
    NSNumber *tweaks = [_preferenceManager preferenceValueForKey:@"tweakInjectionEnabled"];
    return tweaks == nil ? YES : [tweaks boolValue];
}

- (void)sendLog:(NSString*)log debug:(BOOL)debug update:(BOOL)update
{
    if (!self.logView || !log)
        return;

    [_logLock lock];

    [self.logRecord addObject:log];

    BOOL isDebug = self.logView.class == DODebugLogView.class;
    if (debug && !isDebug) {
        [_logLock unlock];
        return;
    }
        
    
    if (update) {
        if ([self.logView respondsToSelector:@selector(updateLog:)]) {
            [self.logView updateLog:log];
        }
    }
    else {
        [self.logView showLog:log];
    }
    [_logLock unlock];
}

- (void)sendLog:(NSString*)log debug:(BOOL)debug
{
    [self sendLog:log debug:debug update:NO];
}

- (NSString *)rootHideStageLogPath
{
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/RootHideStage.log"];
}

- (void)appendSettingsTimingReport:(NSString *)report
{
    NSString *path = [self rootHideStageLogPath];
    NSString *snapshot = [report copy];
    dispatch_async(DOFileDiagnosticsQueue(), ^{
        roothide_stage_file_log(path.fileSystemRepresentation, "%s", snapshot.UTF8String);
    });
}

- (void)shareRootHideStageLogFromView:(UIView *)sourceView
{
    if (_rootHideExportInProgress || !sourceView.window) return;
    _rootHideExportInProgress = YES;
    // Use the already cached path. Do not synchronously query an unhealthy service.
    const char *rootPath = jbinfo(rootPath);
    NSString *root = rootPath ? [NSString stringWithUTF8String:rootPath] : nil;
    struct utsname machine = {0};
    uname(&machine);
    NSString *commit = @"release";
#ifdef NIGHTLY
    commit = @COMMIT_HASH;
#endif
    NSString *header = [NSString stringWithFormat:@"App: %@ (%@)\nDevice: %s / iOS %@\nuid=%u euid=%u",
        [self getLaunchedReleaseTag], commit,
        machine.machine, UIDevice.currentDevice.systemVersion, (unsigned)getuid(), (unsigned)geteuid()];
    NSArray *logs = @[[self rootHideStageLogPath], @ROOTHIDE_JAILBREAKD_STAGE_LOG_PATH,
        @ROOTHIDE_BOOTSTRAP_STAGE_LOG_PATH, @"/var/mobile/Library/Logs/CrashReporter/Dopamine-systemhook-init.log",
        @"/var/mobile/Library/Logs/CrashReporter/Dopamine-app-startup-0.log",
        @"/var/mobile/Library/Logs/CrashReporter/Dopamine-app-startup-501.log"];
    NSArray *crashDirectories = @[@"/var/mobile/Library/Logs/CrashReporter", @"/var/mobile/Library/Logs/CrashReporter/Retired",
        @"/Library/Logs/CrashReporter", @"/var/root/Library/Logs/CrashReporter"];
    dispatch_async(DOFileDiagnosticsQueue(), ^{
        NSString *report = DORootHideDiagnosticReport(header, logs, crashDirectories, root, [NSDate date]);
        NSString *directory = [NSTemporaryDirectory() stringByAppendingPathComponent:[@"RootHideDiagnostics-" stringByAppendingString:NSUUID.UUID.UUIDString]];
        NSString *path = [directory stringByAppendingPathComponent:@"RootHide-diagnostics.txt"];
        NSError *error = nil;
        BOOL saved = [[NSFileManager defaultManager] createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:&error];
        if (saved) saved = [report writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&error];
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_rootHideExportInProgress = NO;
            UIViewController *presenter = sourceView.window.rootViewController;
            while (presenter.presentedViewController) presenter = presenter.presentedViewController;
            if (!presenter || !saved) {
                [[NSFileManager defaultManager] removeItemAtPath:directory error:nil];
                if (presenter) {
                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Menu_Share_RootHide_Log") message:DOLocalizedString(@"RootHide_Log_Export_Failed") preferredStyle:UIAlertControllerStyleAlert];
                    [alert addAction:[UIAlertAction actionWithTitle:DOLocalizedString(@"Button_OK") style:UIAlertActionStyleDefault handler:nil]];
                    [presenter presentViewController:alert animated:YES completion:nil];
                }
                return;
            }
            UIActivityViewController *share = [[UIActivityViewController alloc] initWithActivityItems:@[[NSURL fileURLWithPath:path]] applicationActivities:nil];
            share.popoverPresentationController.sourceView = sourceView;
            share.popoverPresentationController.sourceRect = sourceView.bounds;
            share.completionWithItemsHandler = ^(UIActivityType activityType, BOOL completed, NSArray *returnedItems, NSError *activityError) {
                dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                    [[NSFileManager defaultManager] removeItemAtPath:directory error:nil];
                });
            };
            [presenter presentViewController:share animated:YES completion:nil];
        });
    });
}

- (void)queryRootHideRuntimeIdentityFromView:(UIView *)sourceView
{
    if (!sourceView.window) return;
    __weak UIView *weakView = sourceView;
    void (^show)(NSString *) = ^(NSString *message) {
        UIView *view = weakView;
        UIViewController *presenter = view.window.rootViewController;
        while (presenter.presentedViewController) presenter = presenter.presentedViewController;
        if (!presenter) return;
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Runtime_Identity_Title") message:message preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:DOLocalizedString(@"Button_OK") style:UIAlertActionStyleDefault handler:nil]];
        [presenter presentViewController:alert animated:YES completion:nil];
    };
    BOOL started = DORuntimeIdentityQueryStart(5.0, ^enum rh_runtime_identity_status(struct rh_runtime_identity *out) {
        return jbclient_dopamine_runtime_identity(out);
    }, ^(BOOL timedOut, enum rh_runtime_identity_status status, struct rh_runtime_identity value) {
        if (timedOut) { show(DOLocalizedString(@"Runtime_Identity_Timeout")); return; }
        switch (status) {
            case RH_RUNTIME_REPORTED:
                show([NSString stringWithFormat:@"%@\nfirstLoad=%@\nhandler UUID: %s\ncredential UUID: %s",
                    DOLocalizedString(@"Runtime_Identity_Reported"), value.first_load ? @"true" : @"false", value.handler_uuid, value.credential_uuid]);
                break;
            case RH_RUNTIME_UNSUPPORTED: show(DOLocalizedString(@"Runtime_Identity_Unsupported")); break;
            case RH_RUNTIME_UNKNOWN_IMAGE: show(DOLocalizedString(@"Runtime_Identity_Unknown")); break;
            case RH_RUNTIME_MALFORMED: show(DOLocalizedString(@"Runtime_Identity_Malformed")); break;
            case RH_RUNTIME_NO_REPLY: show(DOLocalizedString(@"Runtime_Identity_No_Reply")); break;
        }
    });
    if (!started) show(DOLocalizedString(@"Runtime_Identity_Busy"));
}

- (void)shareLogRecordFromView:(UIView *)sourceView
{
    if (self.logRecord.count == 0)
        return;

    NSString *log = [self.logRecord componentsJoinedByString:@"\n"];
    UIActivityViewController *activityViewController = [[UIActivityViewController alloc] initWithActivityItems:@[log] applicationActivities:nil];
    activityViewController.popoverPresentationController.sourceView = sourceView;
    activityViewController.popoverPresentationController.sourceRect = sourceView.bounds;
    [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:activityViewController animated:YES completion:nil];
}

- (void)completeJailbreak
{
    if (!self.logView)
        return;

    [self.logView didComplete];
}

- (void)observeFileDescriptor:(int)fd withCallback:(void (^)(char *line))callbackBlock
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int stdout_pipe[2];
        int stdout_orig[2];
        if (pipe(stdout_pipe) != 0 || pipe(stdout_orig) != 0) {
            return;
        }

        dup2(fd, stdout_orig[1]);
        close(stdout_orig[0]);
        
        dup2(stdout_pipe[1], fd);
        close(stdout_pipe[1]);
        
        char cur = 0;
        char line[1024];
        int line_index = 0;
        ssize_t bytes_read;

        while ((bytes_read = read(stdout_pipe[0], &cur, sizeof(cur))) > 0) {
            @autoreleasepool {
                write(stdout_orig[1], &cur, bytes_read);

                if (cur == '\n') {
                    line[line_index] = '\0';
                    callbackBlock(line);
                    line_index = 0;
                } else {
                    if (line_index < sizeof(line) - 1) {
                        line[line_index++] = cur;
                    }
                }
            }
        }
        close(stdout_pipe[0]);
    });
}

- (void)startLogCapture
{
    [self observeFileDescriptor:STDOUT_FILENO withCallback:^(char *line) {
        NSString *str = [NSString stringWithUTF8String:line];
        [self sendLog:str debug:YES];
    }];
    
    [self observeFileDescriptor:STDERR_FILENO withCallback:^(char *line) {
        NSString *str = [NSString stringWithUTF8String:line];
        [self sendLog:str debug:YES];
    }];
}

- (NSString *)localizedStringForKey:(NSString*)key
{
    NSString *candidate = NSLocalizedString(key, nil);
    if ([candidate isEqualToString:key]) {
        if (!_fallbackLocalizations) {
            _fallbackLocalizations = [NSDictionary dictionaryWithContentsOfFile:[[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"en.lproj/Localizable.strings"]];
        }
        candidate = _fallbackLocalizations[key];
        if (!candidate) candidate = key;
    }
    return candidate;
}

- (UIImage *)renderBootLogo
{
    return [[[DOThemeManager sharedInstance] enabledTheme] generateBootLogo];
}

@end


NSString *DOLocalizedString(NSString *key)
{
    return [[DOUIManager sharedInstance] localizedStringForKey:key];
}
