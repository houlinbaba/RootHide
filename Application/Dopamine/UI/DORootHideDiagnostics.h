#ifndef DO_ROOT_HIDE_DIAGNOSTICS_H
#define DO_ROOT_HIDE_DIAGNOSTICS_H

#import <Foundation/Foundation.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// File inspection only: exporting diagnostics must not wait for jailbreak services.
static NSData *DODiagnosticRead(NSString *path, NSUInteger limit, BOOL tail, NSString **status)
{
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        *status = [NSString stringWithFormat:@"unreadable (errno=%d)", errno];
        return nil;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        *status = @"not a readable regular file";
        close(fd);
        return nil;
    }
    if (!tail && (uint64_t)st.st_size > limit) {
        *status = [NSString stringWithFormat:@"omitted: %lld bytes exceeds %lu-byte crash limit", (long long)st.st_size, (unsigned long)limit];
        close(fd);
        return nil;
    }
    off_t offset = tail && (uint64_t)st.st_size > limit ? st.st_size - (off_t)limit : 0;
    NSUInteger length = (NSUInteger)MIN((uint64_t)st.st_size, (uint64_t)limit);
    NSMutableData *data = [NSMutableData dataWithLength:length];
    NSUInteger used = 0;
    while (used < length) {
        ssize_t count = pread(fd, (char *)data.mutableBytes + used, MIN(length - used, (NSUInteger)16384), offset + (off_t)used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            *status = [NSString stringWithFormat:@"read failed (errno=%d)", errno];
            close(fd);
            return nil;
        }
        if (count == 0) break;
        used += (NSUInteger)count;
    }
    struct stat after;
    if (!tail && (used != length || fstat(fd, &after) != 0 || after.st_size != st.st_size || after.st_mtime != st.st_mtime)) {
        *status = @"omitted: crash file changed during read";
        close(fd);
        return nil;
    }
    close(fd);
    data.length = used;
    *status = offset > 0 ? @"truncated: newest log bytes only" : @"readable";
    return data;
}

static void DOAppendDiagnosticFile(NSMutableString *report, NSString *path, NSUInteger limit, BOOL tail)
{
    NSString *status = nil;
    NSData *data = DODiagnosticRead(path, limit, tail, &status);
    // A tail can start inside a UTF-8 character. Skip at most its continuation bytes.
    NSUInteger start = 0;
    const unsigned char *bytes = data.bytes;
    while (tail && start < MIN(data.length, (NSUInteger)3) && (bytes[start] & 0xc0) == 0x80) start++;
    if (start) data = [data subdataWithRange:NSMakeRange(start, data.length - start)];
    NSString *text = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
    if (data && !text) {
        text = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
        status = [status stringByAppendingString:@"; invalid UTF-8, shown as Latin-1"];
    }
    [report appendFormat:@"\n\n--- %@ ---\n%@\n%@", path, status, text ?: @""];
}

static NSString *DODiagnosticCrashProcess(NSString *name)
{
    NSString *lower = name.lowercaseString;
    if (![lower.pathExtension isEqualToString:@"ips"]) return nil;
    for (NSString *process in @[@"sileo", @"roothide"]) {
        if ([lower hasPrefix:[process stringByAppendingString:@"-"]]) return process;
    }
    return nil;
}

static void DOAppendDiagnosticCrashes(NSMutableString *report, NSArray<NSString *> *directories, NSDate *now)
{
    NSMutableDictionary<NSString *, NSMutableArray<NSDictionary *> *> *newest = [NSMutableDictionary dictionary];
    for (NSString *directory in directories) {
        DIR *dir = opendir(directory.fileSystemRepresentation);
        if (!dir) {
            [report appendFormat:@"\nCrash directory %@: unreadable (errno=%d)", directory, errno];
            continue;
        }
        NSUInteger scanned = 0;
        struct dirent *entry;
        while (scanned < 4096 && (entry = readdir(dir))) {
            scanned++;
            NSString *name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:entry->d_name length:strlen(entry->d_name)];
            NSString *process = DODiagnosticCrashProcess(name);
            if (!process) continue;
            NSString *path = [directory stringByAppendingPathComponent:name];
            struct stat st;
            if (lstat(path.fileSystemRepresentation, &st) != 0 || !S_ISREG(st.st_mode)) continue;
            // Include only the last week, with a small allowance for clock skew.
            NSTimeInterval age = now.timeIntervalSince1970 - (NSTimeInterval)st.st_mtime;
            if (age > 7 * 24 * 60 * 60 || age < -300) continue;
            NSMutableArray *items = newest[process];
            if (!items) newest[process] = items = [NSMutableArray array];
            [items addObject:@{@"path": path, @"mtime": @((long long)st.st_mtime)}];
            [items sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
                NSComparisonResult order = [b[@"mtime"] compare:a[@"mtime"]];
                return order == NSOrderedSame ? [a[@"path"] compare:b[@"path"]] : order;
            }];
            if (items.count > 2) [items removeLastObject];
        }
        if (scanned == 4096) [report appendFormat:@"\nCrash directory %@: scan limit reached; selection may be incomplete", directory];
        closedir(dir);
    }
    for (NSString *process in @[@"sileo", @"roothide"]) {
        NSArray *items = newest[process];
        if (!items.count) [report appendFormat:@"\nNo recent readable %@ .ips found. This does not establish whether the App crashed.", process];
        for (NSDictionary *item in items) {
            // Keep each .ips complete or explicitly omit it; never silently cut crash JSON.
            DOAppendDiagnosticFile(report, item[@"path"], 1024 * 1024, NO);
        }
    }
}

static void DOAppendDiagnosticPath(NSMutableString *report, NSString *path)
{
    struct stat st;
    if (lstat(path.fileSystemRepresentation, &st) != 0) {
        [report appendFormat:@"\n%@: lstat failed (errno=%d)", path, errno];
        return;
    }
    [report appendFormat:@"\n%@: mode=%o uid=%u gid=%u bytes=%lld", path, (unsigned)st.st_mode,
        (unsigned)st.st_uid, (unsigned)st.st_gid, (long long)st.st_size];
    if (S_ISLNK(st.st_mode)) {
        char target[PATH_MAX];
        ssize_t length = readlink(path.fileSystemRepresentation, target, sizeof(target) - 1);
        if (length >= 0) {
            target[length] = 0;
            [report appendFormat:@" link=%@", [NSString stringWithUTF8String:target] ?: @"<non-UTF8>"];
        } else {
            [report appendFormat:@" readlink failed (errno=%d)", errno];
        }
    }
    char resolved[PATH_MAX];
    if (realpath(path.fileSystemRepresentation, resolved)) {
        [report appendFormat:@" resolved=%@", [NSString stringWithUTF8String:resolved] ?: @"<non-UTF8>"];
    } else {
        [report appendFormat:@" realpath failed (errno=%d)", errno];
    }
}

static NSString *DORootHideDiagnosticReport(NSString *header, NSArray<NSString *> *logs,
                                          NSArray<NSString *> *crashDirectories, NSString *root, NSDate *now)
{
    NSMutableString *report = [NSMutableString stringWithFormat:@"RootHide diagnostics\n%@\nExported: %@\nOnly RootHide stage/startup logs and recent Sileo/RootHide crashes are collected.\nMissing/unreadable files are not proof of success.\n", header, now];
    for (NSString *path in logs) DOAppendDiagnosticFile(report, path, 256 * 1024, YES);
    [report appendString:@"\n\n--- Read-only loader paths (no service health probe) ---"];
    [report appendString:@"\nThe plain systemhook name can be absent after launchd renames it; roothidepatch is an optional bootstrap supplement."];
    if (root.length) {
        DOAppendDiagnosticPath(report, root);
        NSString *rootName = root.lastPathComponent;
        if ([rootName hasPrefix:@".jbroot-"] && rootName.length == 24) {
            NSString *hookName = [NSString stringWithFormat:@"basebin/systemhook-%@.dylib", [rootName substringFromIndex:8]];
            DOAppendDiagnosticPath(report, [root stringByAppendingPathComponent:hookName]);
        }
        for (NSString *relative in @[@"basebin/.version", @"basebin/systemhook.dylib", @"basebin/roothidehooks.dylib",
                                     @"usr/lib/roothideinit.dylib", @"usr/lib/roothidepatch.dylib", @"usr/lib/libroothide.dylib",
                                     @"usr/lib/liblzma.5.dylib", @"usr/lib/libzstd.1.dylib"]) {
            DOAppendDiagnosticPath(report, [root stringByAppendingPathComponent:relative]);
        }
        for (NSString *app in @[@"Sileo", @"RootHide"]) {
            NSString *bundle = [root stringByAppendingPathComponent:[NSString stringWithFormat:@"Applications/%@.app", app]];
            for (NSString *relative in @[app, @".jbroot", @".jbroot/usr/lib/libroothide.dylib"]) {
                DOAppendDiagnosticPath(report, [bundle stringByAppendingPathComponent:relative]);
            }
        }
    } else {
        [report appendString:@"\nNo cached jailbreak root. Loader paths could not be inspected."];
    }
    [report appendString:@"\n\n--- Recent App crashes (up to two per App, last seven days) ---"];
    DOAppendDiagnosticCrashes(report, crashDirectories, now);
    return report.copy;
}

#endif
