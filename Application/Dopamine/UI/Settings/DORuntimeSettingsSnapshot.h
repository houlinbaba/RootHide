#ifndef DO_RUNTIME_SETTINGS_SNAPSHOT_H
#define DO_RUNTIME_SETTINGS_SNAPSHOT_H

#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>

// Call these methods on the main thread. Reads are memory-only.
// At most one service refresh can be pending
// for this shared snapshot, even if a service stops replying entirely.
@interface DORuntimeSettingsSnapshot : NSObject
- (instancetype)initWithLoader:(NSDictionary<NSString *, NSNumber *> *(^)(void))loader;
- (NSNumber *)runtimeValueForKey:(NSString *)key;
- (void)setRuntimeValue:(NSNumber *)value forKey:(NSString *)key;
- (void)refreshWithCompletion:(void (^)(void))completion;
@end

@implementation DORuntimeSettingsSnapshot {
    NSDictionary<NSString *, NSNumber *> *(^_loader)(void);
    dispatch_queue_t _queue;
    NSMutableDictionary<NSString *, NSNumber *> *_values;
    NSMutableDictionary<NSString *, NSNumber *> *_edits;
    NSUInteger _revision;
    BOOL _inFlight, _hasRefreshed;
    NSTimeInterval _lastRefresh;
}

- (instancetype)initWithLoader:(NSDictionary<NSString *, NSNumber *> *(^)(void))loader
{
    if ((self = [super init])) {
        _loader = [loader copy];
        _queue = dispatch_queue_create("com.roothide.settings-read", DISPATCH_QUEUE_SERIAL);
        _values = [NSMutableDictionary dictionary];
        _edits = [NSMutableDictionary dictionary];
    }
    return self;
}

- (NSNumber *)runtimeValueForKey:(NSString *)key
{
    return _values[key];
}

- (void)setRuntimeValue:(NSNumber *)value forKey:(NSString *)key
{
    _values[key] = value;
    _edits[key] = @(++_revision);
}

- (void)refreshWithCompletion:(void (^)(void))completion
{
    NSTimeInterval now = NSProcessInfo.processInfo.systemUptime;
    if (_inFlight || (_hasRefreshed && now - _lastRefresh < 30)) return;
    _inFlight = YES;
    NSUInteger revision = _revision;
    dispatch_async(_queue, ^{
        NSDictionary<NSString *, NSNumber *> *values = self->_loader() ?: @{};
        dispatch_async(dispatch_get_main_queue(), ^{
            for (NSString *key in values) {
                // A late read must not undo a setting the user changed meanwhile.
                if (self->_edits[key].unsignedIntegerValue <= revision) self->_values[key] = values[key];
            }
            self->_lastRefresh = NSProcessInfo.processInfo.systemUptime;
            self->_hasRefreshed = YES;
            self->_inFlight = NO;
            if (completion) completion();
        });
    });
}
@end

#endif
