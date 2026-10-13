#!/usr/bin/env python3
"""Test the production firmware cache with fake archive I/O on macOS.

Windows runs the real C container validator and checks the full Objective-C
downloader's ARC syntax against declarations. No device jailbreak is simulated.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import subprocess
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'Application/Dopamine/Jailbreak'

C_CASES = r'''
#include "DOFirmwareValidation.h"
#include <assert.h>
#include <stdio.h>
int main(int argc, char **argv) {
    unsigned char valid[] = {0x30,23,0x16,4,'I','M','4','P',0x16,4,'s','p','t','m',0x16,1,'1',0x04,6,1,2,3,4,5,6};
    assert(do_firmware_im4p(valid,sizeof(valid),"sptm"));
    assert(!do_firmware_im4p(valid,sizeof(valid),"trxm"));
    assert(!do_firmware_im4p(NULL,0,"sptm"));
    for (size_t i=0;i<sizeof(valid);i++) assert(!do_firmware_im4p(valid,i,"sptm"));
    unsigned char bad[sizeof(valid)+1]; memcpy(bad,valid,sizeof(valid)); bad[sizeof(valid)]=0;
    assert(!do_firmware_im4p(bad,sizeof(bad),"sptm"));
    bad[1]=0x80; assert(!do_firmware_im4p(bad,sizeof(valid),"sptm"));
    bad[1]=0xff; assert(!do_firmware_im4p(bad,sizeof(valid),"sptm"));
    // Exercise malformed nested TLV lengths and tags with the actual parser.
    for (size_t i=0;i<sizeof(valid);i++) for (unsigned v=0;v<256;v++) {
        memcpy(bad,valid,sizeof(valid)); bad[i]=(unsigned char)v;
        (void)do_firmware_im4p(bad,sizeof(valid),"sptm");
    }
    for (int i=1;i<argc;i+=2) {
        assert(i+1<argc); FILE *file=fopen(argv[i],"rb"); assert(file);
        assert(!fseek(file,0,SEEK_END)); long length=ftell(file); assert(length>0);
        rewind(file); unsigned char *data=malloc((size_t)length); assert(data);
        assert(fread(data,1,(size_t)length,file)==(size_t)length); fclose(file);
        assert(do_firmware_im4p(data,(size_t)length,argv[i+1])); free(data);
    }
    puts("PASS: production IM4P validation, truncation, wrong type and malformed DER");
}
'''

DARWIN_CASES = r'''
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <partial/partial.h>
#import <libjailbreak/roothide_stage.h>
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
static NSMutableDictionary<NSString *, NSData *> *archiveFiles;
static NSString *firmwareURL = @"https://updates.cdn-apple.com/test.ipsw";
static BOOL ota;
static int resolves, downloads;
NSString *getFirmwareURL(bool *isOTA) { ++resolves; *isOTA=ota; return firmwareURL; }
void roothide_stage_log(const char *fmt, ...) { (void)fmt; }
@implementation Partial
+ (instancetype)partialZipWithURL:(NSURL *)url error:(NSError **)error {
    (void)url; (void)error; return [self new];
}
- (NSData *)getFileForPath:(NSString *)path error:(NSError **)error {
    ++downloads; NSData *data=archiveFiles[path];
    if (!data && error) *error=[NSError errorWithDomain:@"mock" code:1 userInfo:nil];
    return data;
}
@end

PRODUCTION_SOURCE

static NSData *image(const char *type) {
    unsigned char bytes[]={0x30,23,0x16,4,'I','M','4','P',0x16,4,0,0,0,0,0x16,1,'1',0x04,6,1,2,3,4,5,6};
    memcpy(bytes+10,type,4); return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}
static NSDictionary *component(NSString *path, NSData *data) {
    unsigned char hash[CC_SHA384_DIGEST_LENGTH]; CC_SHA384(data.bytes,(CC_LONG)data.length,hash);
    return @{@"Info":@{@"Path":path}, @"Digest":[NSData dataWithBytes:hash length:sizeof(hash)]};
}
static NSMutableDictionary *fixture(BOOL monitors) {
    archiveFiles=[NSMutableDictionary dictionary];
    NSArray *names=@[@"kernelcache.release.iphone16", @"Firmware/sptm.t8122.release.im4p", @"Firmware/txm.iphoneos.release.im4p"];
    NSArray *keys=@[@"KernelCache", @"Ap,SecurePageTableMonitor", @"Ap,TrustedExecutionMonitor"];
    const char *types[]={"krnl","sptm","trxm"};
    NSMutableDictionary *components=[NSMutableDictionary dictionary];
    for (int i=0;i<(monitors?3:1);i++) {
        NSData *data=image(types[i]); archiveFiles[names[i]]=data;
        components[keys[i]]=component(names[i],data);
    }
    return [@{@"ProductBuildVersion":@"21A360", @"SupportedProductTypes":@[@"iPhone16,2"],
              @"BuildIdentities":@[@{@"Info":@{@"DeviceClass":@"d84ap", @"Variant":@"Customer Erase Install (IPSW)"},
                                      @"Manifest":components}]} mutableCopy];
}
static void setManifest(NSDictionary *manifest) {
    archiveFiles[@"BuildManifest.plist"]=[NSPropertyListSerialization dataWithPropertyList:manifest format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
}
static NSDictionary *get(NSString *cache, BOOL requiresSPTM, NSError **error) {
    return [DOFirmwareManager firmwareForDevice:@"iPhone16,2" board:@"D84AP" build:@"21A360" requiresSPTM:requiresSPTM cacheDirectory:cache error:error];
}
static NSString *base(NSString *cache) { return [cache stringByAppendingPathComponent:@"iPhone16,2-d84ap-21A360"]; }
static void noPartialCache(NSString *cache) {
    NSArray *files=[NSFileManager.defaultManager contentsOfDirectoryAtPath:base(cache) error:NULL];
    assert(!files.count);
}
int main(void) {
    @autoreleasepool {
        NSString *root=[NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
        NSFileManager *fm=NSFileManager.defaultManager;
        NSError *error=nil;
        NSMutableDictionary *manifest=fixture(YES); setManifest(manifest);
        NSString *cache=[root stringByAppendingPathComponent:@"success"];
        NSDictionary *paths=get(cache,YES,&error); assert(paths.count==3 && !error);
        int before=resolves, beforeDownloads=downloads;
        archiveFiles=nil; // A verified cache must work offline.
        assert(get(cache,YES,&error).count==3 && !error && resolves==before && downloads==beforeDownloads);

        // Corruption forces a complete new generation, never a mixed set.
        [@"broken" writeToFile:paths[@"kernelcache"] atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        manifest=fixture(YES); setManifest(manifest);
        NSDictionary *replacement=get(cache,YES,&error);
        assert(replacement.count==3 && ![replacement[@"kernelcache"] isEqual:paths[@"kernelcache"]] && resolves==before+1);

        cache=[root stringByAppendingPathComponent:@"interrupted"];
        [archiveFiles removeObjectForKey:@"Firmware/txm.iphoneos.release.im4p"];
        assert(!get(cache,YES,&error) && error); noPartialCache(cache);
        manifest=fixture(YES); setManifest(manifest);
        assert(get(cache,YES,&error).count==3 && !error);

        cache=[root stringByAppendingPathComponent:@"bad-digest"];
        manifest=fixture(YES); setManifest(manifest);
        NSMutableData *corrupt=[archiveFiles[@"Firmware/sptm.t8122.release.im4p"] mutableCopy];
        ((unsigned char *)corrupt.mutableBytes)[corrupt.length-1]^=1;
        archiveFiles[@"Firmware/sptm.t8122.release.im4p"]=corrupt;
        assert(!get(cache,YES,&error) && error); noPartialCache(cache);

        cache=[root stringByAppendingPathComponent:@"wrong-container"];
        manifest=fixture(YES);
        NSMutableDictionary *wrongIdentity=[manifest[@"BuildIdentities"][0] mutableCopy];
        NSMutableDictionary *wrongImages=[wrongIdentity[@"Manifest"] mutableCopy];
        NSData *wrongType=image("trxm");
        wrongImages[@"Ap,SecurePageTableMonitor"]=component(@"Firmware/sptm.t8122.release.im4p",wrongType);
        archiveFiles[@"Firmware/sptm.t8122.release.im4p"]=wrongType;
        wrongIdentity[@"Manifest"]=wrongImages; manifest[@"BuildIdentities"]=@[wrongIdentity]; setManifest(manifest);
        assert(!get(cache,YES,&error) && error); noPartialCache(cache);

        manifest=fixture(YES); setManifest(manifest);
        NSString *blocked=[root stringByAppendingPathComponent:@"not-a-directory"];
        assert([@"block" writeToFile:blocked atomically:YES encoding:NSUTF8StringEncoding error:NULL]);
        assert(!get(blocked,YES,&error) && error);

        cache=[root stringByAppendingPathComponent:@"marker-write-failure"];
        NSString *blockedMarker=[base(cache) stringByAppendingPathComponent:@"current.plist"];
        assert([fm createDirectoryAtPath:blockedMarker withIntermediateDirectories:YES attributes:nil error:NULL]);
        assert(!get(cache,YES,&error) && error);
        NSArray *remaining=[fm contentsOfDirectoryAtPath:base(cache) error:NULL];
        assert(remaining.count==1 && [remaining[0] isEqual:@"current.plist"]);

        manifest=fixture(YES); manifest[@"ProductBuildVersion"]=@"21A327"; setManifest(manifest);
        assert(!get([root stringByAppendingPathComponent:@"wrong-build"],YES,&error) && error);
        manifest=fixture(YES); manifest[@"SupportedProductTypes"]=@[@"iPhone16,1"]; setManifest(manifest);
        assert(!get([root stringByAppendingPathComponent:@"wrong-model"],YES,&error) && error);
        manifest=fixture(YES); NSMutableDictionary *identity=[manifest[@"BuildIdentities"][0] mutableCopy];
        identity[@"Info"]=@{@"DeviceClass":@"d83ap",@"Variant":@"Customer"}; manifest[@"BuildIdentities"]=@[identity]; setManifest(manifest);
        assert(!get([root stringByAppendingPathComponent:@"wrong-board"],YES,&error) && error);

        manifest=fixture(NO); setManifest(manifest);
        assert(!get([root stringByAppendingPathComponent:@"missing-monitors"],YES,&error) && error);
        assert(get([root stringByAppendingPathComponent:@"ppl"],NO,&error).count==1 && !error);
        manifest=fixture(YES); setManifest(manifest);
        // Firmware identity also detects SPTM when DeviceTree is inaccessible.
        assert(get([root stringByAppendingPathComponent:@"unknown-registry"],NO,&error).count==3 && !error);

        identity=[manifest[@"BuildIdentities"][0] mutableCopy];
        NSMutableDictionary *images=[identity[@"Manifest"] mutableCopy]; [images removeObjectForKey:@"Ap,TrustedExecutionMonitor"];
        identity[@"Manifest"]=images; manifest[@"BuildIdentities"]=@[identity]; setManifest(manifest);
        assert(!get([root stringByAppendingPathComponent:@"partial-pair"],NO,&error) && error);

        manifest=fixture(YES); identity=[manifest[@"BuildIdentities"][0] mutableCopy];
        identity[@"Info"]=@{@"DeviceClass":@"d84ap",@"Variant":@"Research Erase"};
        manifest[@"BuildIdentities"]=@[identity,manifest[@"BuildIdentities"][0]]; setManifest(manifest);
        assert(get([root stringByAppendingPathComponent:@"research-skip"],YES,&error).count==3);

        manifest=fixture(YES); identity=[manifest[@"BuildIdentities"][0] mutableCopy]; images=[identity[@"Manifest"] mutableCopy];
        images[@"KernelCache"]=component(@"../kernelcache",image("krnl")); identity[@"Manifest"]=images;
        manifest[@"BuildIdentities"]=@[identity]; setManifest(manifest);
        assert(!get([root stringByAppendingPathComponent:@"bad-path"],YES,&error) && error);

        manifest=fixture(YES); setManifest(manifest); ota=YES;
        NSMutableDictionary *otaFiles=[NSMutableDictionary dictionary];
        for (NSString *name in archiveFiles) otaFiles[[@"AssetData/boot" stringByAppendingPathComponent:name]]=archiveFiles[name];
        archiveFiles=otaFiles;
        assert(get([root stringByAppendingPathComponent:@"ota"],YES,&error).count==3 && !error);
        ota=NO; firmwareURL=@"https://example.com/not-apple.ipsw";
        assert(!get([root stringByAppendingPathComponent:@"bad-host"],YES,&error) && error);
        [fm removeItemAtPath:root error:NULL];
        puts("PASS: firmware acquisition, offline cache, corruption, interrupted TXM, identity/digest validation, SPTM pairing and OTA");
    }
}
'''

SYNTAX_PREFIX = r'''
typedef signed char BOOL;
typedef unsigned long NSUInteger, size_t;
typedef unsigned char uint8_t;
typedef unsigned int CC_LONG;
typedef _Bool bool;
#define true 1
#define false 0
#define YES ((BOOL)1)
#define NO ((BOOL)0)
#define nil ((void *)0)
#define NULL ((void *)0)
#define SIZE_MAX ((size_t)-1)
#define NSNotFound ((NSUInteger)-1)
#define NS_ASSUME_NONNULL_BEGIN
#define NS_ASSUME_NONNULL_END
#define CC_SHA384_DIGEST_LENGTH 48
#define CC_SHA1_DIGEST_LENGTH 20
#define NSDataReadingMappedIfSafe 1
#define NSDataWritingAtomic 1
#define NSPropertyListImmutable 0
#define NSPropertyListBinaryFormat_v1_0 200
struct NSRange { NSUInteger location,length; };
extern int memcmp(const void *,const void *,size_t);
extern unsigned char *CC_SHA384(const void *,CC_LONG,unsigned char *);
extern unsigned char *CC_SHA1(const void *,CC_LONG,unsigned char *);
#import <libjailbreak/roothide_stage.h>
@class NSString, NSData, NSError, NSDictionary, NSArray, NSCharacterSet, NSURL;
@protocol NSFastEnumeration
- (NSUInteger)countByEnumeratingWithState:(void *)state objects:(id *)objects count:(NSUInteger)count;
@end
__attribute__((objc_root_class)) @interface NSObject
+ (Class)class;
+ (instancetype)new;
- (BOOL)isKindOfClass:(Class)class;
- (BOOL)isEqual:(id)value;
- (id)mutableCopy;
@end
@interface NSString : NSObject
@property(readonly) NSUInteger length;
@property(readonly) const char *UTF8String;
@property(readonly) NSString *lowercaseString;
@property(readonly) BOOL isAbsolutePath;
@property(readonly) NSArray *pathComponents;
+ (instancetype)stringWithFormat:(NSString *)format,...;
- (BOOL)isEqualToString:(NSString *)value;
- (BOOL)hasPrefix:(NSString *)value;
- (BOOL)hasSuffix:(NSString *)value;
- (struct NSRange)rangeOfCharacterFromSet:(NSCharacterSet *)set;
- (NSString *)stringByAppendingPathComponent:(NSString *)value;
@end
@interface NSArray<__covariant T> : NSObject <NSFastEnumeration>
@property(readonly) NSUInteger count;
+ (instancetype)arrayWithObjects:(const id *)objects count:(NSUInteger)count;
- (BOOL)containsObject:(id)value;
@end
@interface NSDictionary<__covariant K,__covariant V> : NSObject <NSFastEnumeration>
@property(readonly) NSUInteger count;
+ (instancetype)dictionaryWithObjects:(const id *)objects forKeys:(const id *)keys count:(NSUInteger)count;
+ (instancetype)dictionaryWithContentsOfFile:(NSString *)path;
- (V)objectForKeyedSubscript:(K)key;
@end
@interface NSMutableDictionary<K,V> : NSDictionary<K,V>
+ (instancetype)dictionary;
- (void)setObject:(V)object forKeyedSubscript:(K)key;
@end
@interface NSCharacterSet : NSObject
@property(readonly) NSCharacterSet *invertedSet;
+ (instancetype)characterSetWithCharactersInString:(NSString *)value;
@end
@interface NSData : NSObject
@property(readonly) const void *bytes;
@property(readonly) NSUInteger length;
+ (instancetype)dataWithContentsOfFile:(NSString *)path;
+ (instancetype)dataWithContentsOfFile:(NSString *)path options:(NSUInteger)options error:(NSError **)error;
- (BOOL)writeToFile:(NSString *)path options:(NSUInteger)options error:(NSError **)error;
@end
@interface NSError : NSObject
@property(readonly) NSString *localizedDescription;
+ (instancetype)errorWithDomain:(NSString *)domain code:(long)code userInfo:(NSDictionary *)info;
@end
extern NSString *NSLocalizedDescriptionKey, *NSUnderlyingErrorKey;
@interface NSPropertyListSerialization : NSObject
+ (id)propertyListWithData:(NSData *)data options:(NSUInteger)options format:(void *)format error:(NSError **)error;
+ (NSData *)dataWithPropertyList:(id)data format:(NSUInteger)format options:(NSUInteger)options error:(NSError **)error;
@end
@interface NSURL : NSObject
@property(readonly) NSString *scheme,*host,*user,*password;
+ (instancetype)URLWithString:(NSString *)value;
@end
@interface NSURLComponents : NSObject
@property NSString *scheme;
@property(readonly) NSURL *URL;
+ (instancetype)componentsWithURL:(NSURL *)url resolvingAgainstBaseURL:(BOOL)resolve;
@end
@interface NSUUID : NSObject
@property(readonly) NSString *UUIDString;
+ (instancetype)UUID;
@end
@interface NSFileManager : NSObject
+ (instancetype)defaultManager;
- (BOOL)createDirectoryAtPath:(NSString *)path withIntermediateDirectories:(BOOL)parents attributes:(NSDictionary *)attributes error:(NSError **)error;
- (BOOL)removeItemAtPath:(NSString *)path error:(NSError **)error;
@end
'''

INTEGRATION_PREFIX = r'''
#define NSUTF8StringEncoding 4
#define NSPropertyListXMLFormat_v1_0 100
#define assert(value) ((void)sizeof(value))
extern int puts(const char *);
extern void *memcpy(void *, const void *, size_t);
extern void *memchr(const void *, int, size_t);
extern NSString *NSTemporaryDirectory(void), *NSHomeDirectory(void);
@interface NSString (FirmwareTest)
@property(readonly) const char *fileSystemRepresentation;
+ (instancetype)stringWithUTF8String:(const char *)value;
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)atomic encoding:(NSUInteger)encoding error:(NSError **)error;
@end
@interface NSData (FirmwareTest)
+ (instancetype)dataWithBytes:(const void *)data length:(NSUInteger)length;
@end
@interface NSMutableData : NSData
@property(readonly) void *mutableBytes;
@end
@interface NSArray<T> (FirmwareTest)
- (T)objectAtIndexedSubscript:(NSUInteger)index;
@end
@interface NSMutableDictionary<K,V> (FirmwareTest)
- (void)removeObjectForKey:(K)key;
@end
@interface NSFileManager (FirmwareTest)
- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error;
@end

typedef unsigned int uint32_t, io_registry_entry_t;
typedef const void *CFArrayRef;
typedef struct { long location,length; } CFRange;
#define IO_OBJECT_NULL 0
#define kIOMainPortDefault 0
#define kIORegistryEntryPropertyKeysKey 0
#define kCFAllocatorDefault NULL
#define CFSTR(value) ((const void *)0)
#define CPUFAMILY_ARM_BLIZZARD_AVALANCHE 0xda33d83d
#define CPUFAMILY_ARM_EVEREST_SAWTOOTH 0x8765edea
#define CPUFAMILY_ARM_COLL 0x2876f5b5
extern io_registry_entry_t IORegistryEntryFromPath(unsigned int,const char *);
extern const void *IORegistryEntryCreateCFProperty(io_registry_entry_t,const void *,const void *,unsigned);
extern void IOObjectRelease(io_registry_entry_t), CFRelease(const void *);
extern unsigned long CFGetTypeID(const void *), CFArrayGetTypeID(void);
extern long CFArrayGetCount(CFArrayRef);
extern CFRange CFRangeMake(long,long);
extern BOOL CFArrayContainsValue(CFArrayRef,CFRange,const void *);
extern int sysctlbyname(const char *,void *,size_t *,void *,size_t);
extern unsigned int getuid(void);
struct utsname { char machine[256]; };
extern int uname(struct utsname *);
extern void NSLog(NSString *,...);
@interface DOEnvironmentManager : NSObject
+ (instancetype)sharedManager;
- (BOOL)isInstalledThroughTrollStore;
- (BOOL)isSPTM;
- (NSString *)accessibleKernelPath;
- (NSString *)accessibleSPTMPath;
- (NSString *)accessibleTXMPath;
- (NSDictionary *)prepareKernelImagesWithError:(NSError **)error;
@end
@interface DOUIManager : NSObject
+ (instancetype)sharedInstance;
- (void)sendLog:(NSString *)message debug:(BOOL)debug;
@end
extern NSString *DOLocalizedString(NSString *);
extern NSString *JBErrorDomain;
#define JBErrorCodeFailedToFindKernel -1
#define JBErrorCodeFailedKernelPatchfinding -2
extern int xpf_start_with_kernel_path(const char *,const char *,const char *);
extern void xpf_stop(void);
extern struct { void *sptm,*txm; char *xnuPlatform,*darwinVersion,*xnuBuild; } gXPF;
@interface DOJailbreaker : NSObject
- (NSError *)gatherSystemInformation;
@end
'''

def extract(text, signature):
    start = text.index(signature)
    opening = text.index('{', start)
    depth = 0
    for position in range(opening, len(text)):
        depth += (text[position] == '{') - (text[position] == '}')
        if not depth:
            return text[start:position + 1]
    raise ValueError(signature)

def no_includes(text):
    # Keep stage declarations at their actual include sites so the fixture's
    # mock definition cannot hide a late format attribute declaration.
    return '\n'.join(line for line in text.splitlines()
                     if line == '#import <libjailbreak/roothide_stage.h>'
                     or not line.startswith(('#import ', '#include ')))

def check_linked_api():
    # Check exports in the ranlib indexes, not just strings inside object code.
    for name, symbol in [('libgrabkernel2.a',b'_getFirmwareURL\0'), ('libpartial.a',b'_OBJC_CLASS_$_Partial\0')]:
        data = (ROOT/'Application/Dopamine/Dependencies'/name).read_bytes()
        assert data[:4] == bytes.fromhex('cafebabe')
        count = struct.unpack_from('>I', data, 4)[0]
        for i in range(count):
            _, _, offset, size, _ = struct.unpack_from('>IIIII', data, 8 + i*20)
            archive = data[offset:offset+size]
            assert archive.startswith(b'!<arch>\n')
            member_size = int(archive[8+48:8+58])
            member = archive[8+60:8+60+member_size]
            assert member.startswith(b'__.SYMDEF') and symbol in member
            if name == 'libpartial.a':
                assert b'getFileForPath:error:\0' in archive and b'partialZipWithURL:error:\0' in archive
    print('PASS: required firmware resolver and Partial API present in both bundled library architectures')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--reference', type=Path, help='Optional real Apple firmware components to validate')
    parser.add_argument('--workdir', type=Path, help='Existing writable scratch directory')
    args = parser.parse_args()
    check_linked_api()
    context = nullcontext(str(args.workdir.resolve())) if args.workdir else tempfile.TemporaryDirectory(prefix='firmware-regression-')
    with context as directory:
        temp = Path(directory)
        include = temp / 'libjailbreak'; include.mkdir(exist_ok=True)
        (include/'roothide_stage.h').write_text('void roothide_stage_log(const char *, ...) __attribute__((format(printf,1,2)));\n', encoding='utf-8')
        harness = temp / 'validator.c'
        harness.write_text('#include <stdlib.h>\n' + C_CASES, encoding='utf-8')
        binary = temp / ('validator.exe' if args.zig else 'validator')
        compiler = [str(args.zig), 'cc'] if args.zig else ['cc']
        subprocess.run(compiler + ['-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(SOURCE), str(harness), '-o', str(binary)], check=True)
        command = [str(binary)]
        if args.reference:
            for name, kind in [('kernelcache','krnl'), ('sptm.im4p','sptm'), ('txm.im4p','trxm')]: command += [str(args.reference / name),kind]
        subprocess.run(command, check=True, timeout=30)
        if args.zig:
            syntax = temp / 'firmware.m'
            text = SYNTAX_PREFIX + no_includes((SOURCE/'DOFirmwareValidation.h').read_text()) + '\n'
            text += no_includes((ROOT/'BaseBin/_external/include/partial/partial.h').read_text()) + '\n'
            text += no_includes((SOURCE/'DOFirmwareManager.h').read_text()) + '\n'
            text += no_includes((SOURCE/'DOFirmwareManager.m').read_text())
            syntax.write_text(text, encoding='utf-8')
            subprocess.run([str(args.zig), 'clang', '-cc1', '-triple', 'arm64-apple-ios17.0.0', '-x', 'objective-c',
                            '-fobjc-runtime=ios-17.0.0', '-fobjc-arc', '-fblocks', '-fobjc-exceptions', '-Wall', '-Wextra',
                            '-Werror', '-Wno-nullability-completeness', '-I', str(temp), '-fsyntax-only', str(syntax)], check=True)
            print('PASS: full firmware downloader Objective-C/ARC syntax (declarations only)')
            # Also check the entire Darwin fixture before adding it to Apple CI.
            headers = SYNTAX_PREFIX + INTEGRATION_PREFIX
            headers += no_includes((ROOT/'BaseBin/_external/include/partial/partial.h').read_text()) + '\n'
            production = no_includes((SOURCE/'DOFirmwareValidation.h').read_text()) + '\n'
            production += no_includes((SOURCE/'DOFirmwareManager.h').read_text()) + '\n'
            production += no_includes((SOURCE/'DOFirmwareManager.m').read_text())
            # Unlike the downloader/preflight checks, this fixture must obtain
            # the attributed declaration from its own imports before the mock.
            fixture_headers = headers.replace('#import <libjailbreak/roothide_stage.h>\n', '')
            syntax.write_text(fixture_headers + no_includes(DARWIN_CASES.replace('PRODUCTION_SOURCE', production)), encoding='utf-8')
            check = [str(args.zig), 'clang', '-cc1', '-triple', 'arm64-apple-ios17.0.0', '-x', 'objective-c',
                     '-fobjc-runtime=ios-17.0.0', '-fobjc-arc', '-fblocks', '-fobjc-exceptions', '-Wall', '-Wextra',
                     '-Werror', '-Wno-nullability-completeness', '-Wno-incomplete-implementation', '-I', str(temp), '-fsyntax-only', str(syntax)]
            subprocess.run(check, check=True)
            # Reproduce the original CI failure by removing only the fixture's
            # early import. The production source still imports the same header.
            late = temp / 'late-stage-declaration.m'
            broken_fixture = DARWIN_CASES.replace('#import <libjailbreak/roothide_stage.h>\n', '')
            late.write_text(fixture_headers + no_includes(broken_fixture.replace('PRODUCTION_SOURCE', production)), encoding='utf-8')
            result = subprocess.run(check[:-1] + [str(late)], capture_output=True, text=True)
            if result.returncode == 0 or '-Wignored-attributes' not in result.stderr:
                raise RuntimeError('Fixture check did not detect the late stage-log format attribute: ' + result.stderr)
            print('PASS: fixture imports stage-log attributes before the mock; late declaration rejected under -Werror')
            environment = (SOURCE/'DOEnvironmentManager.m').read_text(encoding='utf-8')
            jailbreaker = (SOURCE/'DOJailbreaker.m').read_text(encoding='utf-8')
            preflight = extract(jailbreaker, '- (NSError *)gatherSystemInformation')
            preflight = preflight[:preflight.index('        char *sets[99]')] + '    }\n    return nil;\n}'
            integration = headers + no_includes((SOURCE/'DOFirmwareManager.h').read_text()) + '\n'
            integration += '@implementation DOEnvironmentManager\n' + extract(environment, '- (BOOL)isSPTM') + '\n'
            integration += extract(environment, '- (NSDictionary<NSString *, NSString *> *)prepareKernelImagesWithError:') + '\n@end\n'
            integration += '@implementation DOJailbreaker\n' + preflight + '\n@end\n'
            syntax.write_text(integration, encoding='utf-8')
            subprocess.run(check, check=True)
            print('PASS: Darwin fixture, SPTM detection and jailbreak firmware preflight syntax (declarations only)')
        elif sys.platform == 'darwin':
            harness = temp / 'firmware.m'
            production = '#include "' + (SOURCE/'DOFirmwareManager.m').as_posix() + '"'
            harness.write_text(DARWIN_CASES.replace('PRODUCTION_SOURCE',production), encoding='utf-8')
            binary = temp / 'firmware'
            subprocess.run(['xcrun','clang','-fobjc-arc','-fblocks','-fobjc-exceptions','-Wall','-Wextra','-Werror',
                            '-Wno-deprecated-declarations','-fsanitize=address,undefined','-I',str(temp),
                            '-I',str(ROOT/'BaseBin/_external/include'),'-framework','Foundation',str(harness),'-o',str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=60)
        else:
            print('Foundation cache regressions require macOS; pass --zig for Windows syntax checks.')

if __name__ == '__main__':
    main()
