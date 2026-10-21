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

static NSArray<NSString *> *DODiagnosticTargetProcesses(void)
{
    return @[@"sileo", @"roothide", @"launchd", @"newterm", @"newterm2", @"terminal",
             @"newtermloginhelper", @"login", @"zsh", @"bash", @"dash"];
}

static NSString *DODiagnosticCrashProcess(NSString *name)
{
    NSString *lower = name.lowercaseString;
    if (![lower.pathExtension isEqualToString:@"ips"] &&
        ![lower.pathExtension isEqualToString:@"crash"] &&
        ![lower hasSuffix:@".ips.ca.synced"] && ![lower hasSuffix:@".ips.synced"]) return nil;
    for (NSString *process in DODiagnosticTargetProcesses()) {
        if ([lower hasPrefix:[process stringByAppendingString:@"-"]]) return process;
    }
    return nil;
}

static NSArray<NSString *> *DODiagnosticCrashDirectories(NSArray<NSString *> *directories, NSString *root)
{
    NSMutableOrderedSet<NSString *> *paths = [NSMutableOrderedSet orderedSetWithArray:directories];
    // RootHide can redirect a jailbreak App's home/log paths into its bootstrap.
    // Keep both locations; these inspections do not query a jailbreak service.
    if (root.length) {
        for (NSString *relative in @[@"var/mobile/Library/Logs/CrashReporter",
                                     @"var/mobile/Library/Logs/CrashReporter/Retired"]) {
            [paths addObject:[root stringByAppendingPathComponent:relative]];
        }
    }
    return paths.array;
}

static void DOAppendDiagnosticCrashes(NSMutableString *report, NSArray<NSString *> *directories, NSDate *now)
{
    NSMutableDictionary<NSString *, NSMutableArray<NSDictionary *> *> *newest = [NSMutableDictionary dictionary];
    NSMutableSet<NSString *> *seenFiles = [NSMutableSet set];
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
            // Alias directories must not let the same file occupy both slots.
            NSString *identity = [NSString stringWithFormat:@"%llu:%llu", (unsigned long long)st.st_dev, (unsigned long long)st.st_ino];
            if ([seenFiles containsObject:identity]) continue;
            [seenFiles addObject:identity];
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
    for (NSString *process in DODiagnosticTargetProcesses()) {
        NSArray *items = newest[process];
        if (!items.count) [report appendFormat:@"\nNo recent %@ crash file found. This does not establish whether the process crashed.", process];
        for (NSDictionary *item in items) {
            // Keep each crash file complete or explicitly omit it.
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
    NSMutableString *report = [NSMutableString stringWithFormat:@"RootHide diagnostics\n%@\nExported: %@\nCollected: RootHide stage/startup/timing logs, bounded bootstrap APT/dpkg logs and recent Sileo/RootHide/launchd/terminal/login/shell crashes.\nMissing/unreadable files are not proof of success or of missing components.\nSession Ended can occur without a crash report.\n", header, now];
    for (NSString *path in logs) DOAppendDiagnosticFile(report, path, 256 * 1024, YES);
    if (root.length) {
        for (NSString *name in @[@"Dopamine-app-startup-0.log", @"Dopamine-app-startup-501.log"]) {
            NSString *relative = [@"var/mobile/Library/Logs/CrashReporter" stringByAppendingPathComponent:name];
            DOAppendDiagnosticFile(report, [root stringByAppendingPathComponent:relative], 256 * 1024, YES);
        }
        [report appendString:@"\n\n--- Package-manager logs (newest 256 KiB per file) ---"];
        for (NSString *relative in @[@"var/log/apt/term.log", @"var/log/apt/history.log", @"var/log/dpkg.log"]) {
            DOAppendDiagnosticFile(report, [root stringByAppendingPathComponent:relative], 256 * 1024, YES);
        }
    }
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
                                     @"usr/lib/liblzma.5.dylib", @"usr/lib/libzstd.1.dylib",
                                     @"usr/bin/login", @"bin/sh", @"usr/bin/zsh", @"usr/bin/bash",
                                     @"etc/pam.d/login"]) {
            DOAppendDiagnosticPath(report, [root stringByAppendingPathComponent:relative]);
        }
        for (NSString *app in @[@"Sileo", @"RootHide"]) {
            NSString *bundle = [root stringByAppendingPathComponent:[NSString stringWithFormat:@"Applications/%@.app", app]];
            for (NSString *relative in @[app, @".jbroot", @".jbroot/usr/lib/libroothide.dylib"]) {
                DOAppendDiagnosticPath(report, [bundle stringByAppendingPathComponent:relative]);
            }
        }
        [report appendString:@"\n\n--- Known terminal bundle paths (absence does not identify the installed terminal) ---"];
        for (NSString *app in @[@"NewTerm", @"NewTerm2", @"Terminal"]) {
            NSString *bundle = [root stringByAppendingPathComponent:[NSString stringWithFormat:@"Applications/%@.app", app]];
            for (NSString *relative in @[app, @"NewTermLoginHelper", @".jbroot"]) {
                DOAppendDiagnosticPath(report, [bundle stringByAppendingPathComponent:relative]);
            }
            NSString *status = nil;
            NSString *infoPath = [bundle stringByAppendingPathComponent:@"Info.plist"];
            NSData *data = DODiagnosticRead(infoPath, 64 * 1024, NO, &status);
            id info = data ? [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:nil] : nil;
            [report appendFormat:@"\n%@: %@", infoPath, status];
            if ([info isKindOfClass:NSDictionary.class]) {
                for (NSString *key in @[@"CFBundleIdentifier", @"CFBundleShortVersionString", @"CFBundleVersion", @"CFBundleExecutable"]) {
                    id value = info[key];
                    if ([value isKindOfClass:NSString.class])
                        [report appendFormat:@" %@=%@", key, [value substringToIndex:MIN((NSUInteger)256, [value length])]];
                }
            }
        }
    } else {
        [report appendString:@"\nNo cached jailbreak root. Loader paths could not be inspected."];
    }
    [report appendString:@"\n\n--- Recent process crashes (up to two per process, last seven days) ---"];
    DOAppendDiagnosticCrashes(report, DODiagnosticCrashDirectories(crashDirectories, root), now);
    return report.copy;
}

#endif
