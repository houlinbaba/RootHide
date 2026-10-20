#import "DOFirmwareManager.h"
#import "DOFirmwareValidation.h"
#import <partial/partial.h>
#import <CommonCrypto/CommonDigest.h>
#import <libjailbreak/roothide_stage.h>

// Exported by the bundled libgrabkernel2.a. Reuse its device/build-aware
// IPSW/full-OTA resolver; libpartial.a is already linked by the App target.
extern NSString *getFirmwareURL(bool *isOTA);

static NSString *const DOFirmwareErrorDomain = @"DOFirmwareErrorDomain";

static void firmwareError(NSError **error, NSString *message, NSError *underlying)
{
    if (!error) return;
    NSMutableDictionary *info = [@{NSLocalizedDescriptionKey:message} mutableCopy];
    if (underlying) info[NSUnderlyingErrorKey] = underlying;
    *error = [NSError errorWithDomain:DOFirmwareErrorDomain code:1 userInfo:info];
}

static BOOL safeFirmwareName(NSString *name)
{
    if (![name isKindOfClass:NSString.class] || !name.length || [name isEqualToString:@"."] || [name isEqualToString:@".."]) return NO;
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,._-"];
    return [name rangeOfCharacterFromSet:allowed.invertedSet].location == NSNotFound;
}

static BOOL safeFirmwarePath(NSString *path)
{
    if (![path isKindOfClass:NSString.class] || !path.length || path.isAbsolutePath) return NO;
    for (NSString *part in path.pathComponents) {
        if (!safeFirmwareName(part)) return NO;
    }
    return YES;
}

static NSDictionary *firmwareComponents(NSDictionary *manifest, NSString *device,
                                         NSString *board, NSString *build, BOOL requiresSPTM,
                                         NSError **error)
{
    if (![manifest isKindOfClass:NSDictionary.class] ||
        ![manifest[@"ProductBuildVersion"] isEqual:build] ||
        ![manifest[@"SupportedProductTypes"] isKindOfClass:NSArray.class] ||
        ![manifest[@"SupportedProductTypes"] containsObject:device] ||
        ![manifest[@"BuildIdentities"] isKindOfClass:NSArray.class]) {
        firmwareError(error, @"Firmware manifest does not match this device and iOS build.", nil);
        return nil;
    }
    for (id item in manifest[@"BuildIdentities"]) {
        if (![item isKindOfClass:NSDictionary.class]) continue;
        NSDictionary *info = item[@"Info"];
        if (![info isKindOfClass:NSDictionary.class]) continue;
        NSString *variant = info[@"Variant"], *deviceClass = info[@"DeviceClass"];
        if (![variant isKindOfClass:NSString.class] || [variant hasPrefix:@"Research"] ||
            ![deviceClass isKindOfClass:NSString.class] || ![deviceClass.lowercaseString isEqual:board.lowercaseString]) continue;
        NSDictionary *images = item[@"Manifest"];
        if (![images isKindOfClass:NSDictionary.class]) continue;
        BOOL hasSPTM = images[@"Ap,SecurePageTableMonitor"] != nil;
        BOOL hasTXM = images[@"Ap,TrustedExecutionMonitor"] != nil;
        if (hasSPTM != hasTXM || (requiresSPTM && !hasSPTM)) continue;
        NSMutableDictionary *components = [@{@"kernelcache":@"KernelCache"} mutableCopy];
        if (hasSPTM) {
            components[@"sptm.im4p"] = @"Ap,SecurePageTableMonitor";
            components[@"txm.im4p"] = @"Ap,TrustedExecutionMonitor";
        }
        NSMutableDictionary *result = [NSMutableDictionary dictionary];
        BOOL valid = YES;
        for (NSString *name in components) {
            NSDictionary *component = images[components[name]];
            if (![component isKindOfClass:NSDictionary.class] || ![component[@"Info"] isKindOfClass:NSDictionary.class]) { valid = NO; break; }
            NSString *path = component[@"Info"][@"Path"];
            NSData *digest = component[@"Digest"];
            if (!safeFirmwarePath(path) || ![digest isKindOfClass:NSData.class] ||
                (digest.length != CC_SHA384_DIGEST_LENGTH && digest.length != CC_SHA1_DIGEST_LENGTH)) { valid = NO; break; }
            result[name] = @{@"path":path, @"digest":digest};
        }
        if (valid) return result;
    }
    firmwareError(error, @"Matching firmware identity is missing required kernel, SPTM or TXM images.", nil);
    return nil;
}

static BOOL firmwareImageMatches(NSData *data, NSString *name, NSData *expected)
{
    const char *type = [name isEqual:@"kernelcache"] ? "krnl" : ([name isEqual:@"sptm.im4p"] ? "sptm" : "trxm");
    if (!do_firmware_im4p(data.bytes, data.length, type)) return NO;
    unsigned char hash[CC_SHA384_DIGEST_LENGTH];
    if (expected.length == CC_SHA384_DIGEST_LENGTH) CC_SHA384(data.bytes, (CC_LONG)data.length, hash);
    else if (expected.length == CC_SHA1_DIGEST_LENGTH) CC_SHA1(data.bytes, (CC_LONG)data.length, hash);
    else return NO;
    return memcmp(hash, expected.bytes, expected.length) == 0;
}

static NSDictionary *validatedFirmwareAtPath(NSString *directory, NSString *device,
                                              NSString *board, NSString *build, BOOL requiresSPTM)
{
    NSData *manifestData = [NSData dataWithContentsOfFile:[directory stringByAppendingPathComponent:@"BuildManifest.plist"]];
    if (!manifestData) return nil;
    NSDictionary *manifest = [NSPropertyListSerialization propertyListWithData:manifestData options:NSPropertyListImmutable format:NULL error:NULL];
    NSDictionary *components = firmwareComponents(manifest, device, board, build, requiresSPTM, NULL);
    if (!components) return nil;
    NSMutableDictionary *paths = [NSMutableDictionary dictionary];
    for (NSString *name in components) {
        NSString *path = [directory stringByAppendingPathComponent:name];
        NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:NULL];
        if (!firmwareImageMatches(data, name, components[name][@"digest"])) return nil;
        paths[name] = path;
    }
    return paths;
}

@implementation DOFirmwareManager
+ (NSDictionary<NSString *, NSString *> *)firmwareForDevice:(NSString *)device
                                                       board:(NSString *)board
                                                       build:(NSString *)build
                                                requiresSPTM:(BOOL)requiresSPTM
                                              cacheDirectory:(NSString *)cacheDirectory
                                                       error:(NSError **)error
{
    if (error) *error = nil;
    if (!safeFirmwareName(device) || !safeFirmwareName(board) || !safeFirmwareName(build)) {
        firmwareError(error, @"Unable to determine this device's firmware identity.", nil);
        return nil;
    }
    // Never expose a partially downloaded set, or mix old Documents/kernelcache
    // with new monitor images. Published generation directories are immutable.
    @synchronized(self) {
        NSFileManager *fm = NSFileManager.defaultManager;
        NSString *key = [NSString stringWithFormat:@"%@-%@-%@", device, board.lowercaseString, build];
        NSString *base = [cacheDirectory stringByAppendingPathComponent:key];
        NSString *markerPath = [base stringByAppendingPathComponent:@"current.plist"];
        NSDictionary *marker = [NSDictionary dictionaryWithContentsOfFile:markerPath];
        NSString *generation = marker[@"generation"];
        if (safeFirmwareName(generation)) {
            NSDictionary *cached = validatedFirmwareAtPath([base stringByAppendingPathComponent:generation], device, board, build, requiresSPTM);
            if (cached) {
                roothide_stage_log("firmware.cache.valid model=%s board=%s build=%s", device.UTF8String, board.UTF8String, build.UTF8String);
                return cached;
            }
        }

        roothide_stage_log("firmware.download.begin model=%s board=%s build=%s requires_sptm=%d", device.UTF8String, board.UTF8String, build.UTF8String, requiresSPTM);
        bool isOTA = false;
        NSString *urlString = getFirmwareURL(&isOTA);
        NSURL *url = [NSURL URLWithString:urlString ?: @""];
        // AppleDB may advertise older HTTP links; use HTTPS for the same host.
        if ([url.scheme.lowercaseString isEqual:@"http"]) {
            NSURLComponents *parts = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
            parts.scheme = @"https";
            url = parts.URL;
        }
        NSString *host = url.host.lowercaseString;
        if (![url.scheme.lowercaseString isEqual:@"https"] ||
            !do_firmware_apple_host(host.UTF8String) || url.user || url.password) {
            firmwareError(error, @"Unable to find matching firmware on Apple's download servers. Check your internet connection.", nil);
            return nil;
        }
        NSError *failure = nil;
        Partial *zip = [Partial partialZipWithURL:url error:&failure];
        if (!zip) {
            firmwareError(error, @"Unable to open the matching firmware download.", failure);
            return nil;
        }
        NSString *prefix = isOTA ? @"AssetData/boot" : @"";
        NSData *manifestData = [zip getFileForPath:[prefix stringByAppendingPathComponent:@"BuildManifest.plist"] error:&failure];
        if (!manifestData) {
            firmwareError(error, @"Unable to download the firmware manifest.", failure);
            return nil;
        }
        NSDictionary *manifest = [NSPropertyListSerialization propertyListWithData:manifestData options:NSPropertyListImmutable format:NULL error:&failure];
        NSDictionary *components = firmwareComponents(manifest, device, board, build, requiresSPTM, error);
        if (!components) return nil;

        generation = NSUUID.UUID.UUIDString;
        NSString *incoming = [base stringByAppendingPathComponent:generation];
        if (![fm createDirectoryAtPath:incoming withIntermediateDirectories:YES attributes:nil error:&failure]) {
            firmwareError(error, @"Unable to create the firmware cache.", failure);
            return nil;
        }
        BOOL published = NO;
        @try {
            for (NSString *name in @[@"kernelcache", @"sptm.im4p", @"txm.im4p"]) {
                NSDictionary *component = components[name];
                if (!component) continue;
                NSString *archivePath = [prefix stringByAppendingPathComponent:component[@"path"]];
                NSData *image = [zip getFileForPath:archivePath error:&failure];
                if (!image) {
                    firmwareError(error, [NSString stringWithFormat:@"Unable to download required firmware image %@.", name], failure);
                    return nil;
                }
                if (!firmwareImageMatches(image, name, component[@"digest"])) {
                    firmwareError(error, [NSString stringWithFormat:@"Firmware image %@ is incomplete or does not match its manifest.", name], nil);
                    return nil;
                }
                if (![image writeToFile:[incoming stringByAppendingPathComponent:name] options:NSDataWritingAtomic error:&failure]) {
                    firmwareError(error, @"Unable to save the downloaded firmware.", failure);
                    return nil;
                }
                roothide_stage_log("firmware.download.image name=%s bytes=%llu digest_verified=1", name.UTF8String, (unsigned long long)image.length);
            }
            if (![manifestData writeToFile:[incoming stringByAppendingPathComponent:@"BuildManifest.plist"] options:NSDataWritingAtomic error:&failure]) {
                firmwareError(error, @"Unable to save the firmware manifest.", failure);
                return nil;
            }
            NSDictionary *paths = validatedFirmwareAtPath(incoming, device, board, build, requiresSPTM);
            NSData *markerData = [NSPropertyListSerialization dataWithPropertyList:@{@"generation":generation} format:NSPropertyListBinaryFormat_v1_0 options:0 error:&failure];
            if (!paths || !markerData || ![markerData writeToFile:markerPath options:NSDataWritingAtomic error:&failure]) {
                firmwareError(error, @"Unable to validate and publish the firmware cache.", failure);
                return nil;
            }
            published = YES;
            roothide_stage_log("firmware.download.end verified=1 images=%llu", (unsigned long long)paths.count);
            return paths;
        }
        @finally {
            if (!published) [fm removeItemAtPath:incoming error:NULL];
        }
    }
}
@end
