#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DOFirmwareManager : NSObject
+ (nullable NSDictionary<NSString *, NSString *> *)firmwareForDevice:(NSString *)device
                                                              board:(NSString *)board
                                                              build:(NSString *)build
                                                       requiresSPTM:(BOOL)requiresSPTM
                                                     cacheDirectory:(NSString *)cacheDirectory
                                                              error:(NSError * _Nullable * _Nullable)error;
@end

NS_ASSUME_NONNULL_END
