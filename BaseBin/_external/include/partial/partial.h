// Public interface of the already bundled dhinakg/partial library (MIT).
// https://github.com/dhinakg/partial/blob/31667c15c069333400432fb0e367ac4787ec5ce0/include/partial.h
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
@interface Partial : NSObject
+ (nullable instancetype)partialZipWithURL:(NSURL *)url error:(NSError **)error;
- (nullable NSData *)getFileForPath:(NSString *)path error:(NSError **)error;
@end
NS_ASSUME_NONNULL_END
