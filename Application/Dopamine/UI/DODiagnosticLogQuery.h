#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#include <libjailbreak/diagnostic_log.h>

// The service opens only fixed log names. File bytes are read here, never by
// launchd. A timeout abandons the result; it cannot cancel synchronous XPC.
static NSString *DODiagnosticDescriptorLogs(int (^query)(uint64_t, int *), NSProgress *progress)
{
    NSMutableString *report = [NSMutableString stringWithString:@"\n\n--- Read-only service log descriptors (not a service health test) ---\n"];
    NSUInteger bytes = 0;
    for (uint64_t selector = 0; selector < RH_DIAGNOSTIC_LOG_COUNT * 2; selector++) {
        if (progress.cancelled) break;
        int fd = -1;
        int result = query(selector, &fd);
        if (progress.cancelled) { if (fd >= 0) close(fd); break; }
        const char *name = rh_diagnostic_log_name(selector % RH_DIAGNOSTIC_LOG_COUNT);
        [report appendFormat:@"\n%s/%s: ", selector < RH_DIAGNOSTIC_LOG_COUNT ? "real" : "bootstrap", name];
        if (result || fd < 0) {
            if (fd >= 0) close(fd);
            [report appendFormat:@"unavailable (result=%d)\n", result ?: EPROTO];
            continue;
        }
        struct stat st;
        int flags = fcntl(fd, F_GETFL);
        if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY ||
            fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 || fstat(fd, &st) != 0 ||
            !S_ISREG(st.st_mode) || st.st_size < 0) {
            close(fd); [report appendString:@"not a readable regular descriptor\n"]; continue;
        }
        NSUInteger length = (NSUInteger)MIN((uint64_t)st.st_size, (uint64_t)65536);
        if (bytes + length > 512 * 1024) { close(fd); [report appendString:@"total byte limit reached\n"]; break; }
        NSMutableData *data = [NSMutableData dataWithLength:length];
        off_t offset = st.st_size - (off_t)length;
        ssize_t count = pread(fd, data.mutableBytes, length, offset);
        int readError = count < 0 ? errno : 0;
        close(fd);
        if (count < 0) { [report appendFormat:@"read failed (errno=%d)\n", readError]; continue; }
        data.length = (NSUInteger)count;
        bytes += data.length;
        NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (!text) text = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
        [report appendFormat:@"%@\n%@\n", offset ? @"newest 65536 bytes only" : @"readable", text ?: @""];
    }
    return report;
}

static BOOL DODiagnosticLogQueryStart(NSTimeInterval deadline,
    int (^query)(uint64_t, int *), void (^completion)(NSString *))
{
    NSCAssert(NSThread.isMainThread, @"Diagnostic query must start on main");
    static BOOL inFlight = NO;
    if (inFlight) return NO;
    inFlight = YES;
    NSProgress *progress = [NSProgress discreteProgressWithTotalUnitCount:RH_DIAGNOSTIC_LOG_COUNT * 2];
    __block BOOL waiting = YES; // Only the main queue reads/writes this flag.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(deadline * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (!waiting) return;
        waiting = NO;
        [progress cancel];
        completion(@"\n\nService log collection timed out. Local logs retained; no service or device success is implied.\n");
    });
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool {
            NSString *report = DODiagnosticDescriptorLogs(query, progress);
            dispatch_async(dispatch_get_main_queue(), ^{
                inFlight = NO;
                if (!waiting) return; // Late data is released without presenting/exporting it.
                waiting = NO;
                completion(report);
            });
        }
    });
    return YES;
}
