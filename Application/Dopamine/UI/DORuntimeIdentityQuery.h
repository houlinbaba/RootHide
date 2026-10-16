#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#include <libjailbreak/runtime_identity.h>

// A query-specific one-worker budget. Timeout stops local UI waiting only.
// If the synchronous transport never returns, the gate stays occupied until
// App exit; retries cannot accumulate blocked workers. All gate state is main.
static BOOL DORuntimeIdentityQueryStart(NSTimeInterval deadline,
    enum rh_runtime_identity_status (^query)(struct rh_runtime_identity *),
    void (^completion)(BOOL, enum rh_runtime_identity_status, struct rh_runtime_identity))
{
    NSCAssert(NSThread.isMainThread, @"Runtime identity query must start on main");
    static BOOL inFlight = NO;
    if (inFlight) return NO;
    inFlight = YES;
    __block BOOL waiting = YES;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(deadline * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (!waiting) return;
        waiting = NO;
        completion(YES, RH_RUNTIME_NO_REPLY, (struct rh_runtime_identity){0});
    });
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        struct rh_runtime_identity value = {0};
        enum rh_runtime_identity_status status = query(&value);
        dispatch_async(dispatch_get_main_queue(), ^{
            inFlight = NO;
            if (!waiting) return; // late result releases its block-owned data here
            waiting = NO;
            completion(NO, status, value);
        });
    });
    return YES;
}
