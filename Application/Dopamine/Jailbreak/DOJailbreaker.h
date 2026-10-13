//
//  Jailbreaker.h
//  Dopamine
//
//  Created by Lars Fröder on 10.01.24.
//

#import <Foundation/Foundation.h>

#import <xpc/xpc.h>
#include <libjailbreak/credential_types.h>

NS_ASSUME_NONNULL_BEGIN

@interface DOJailbreaker : NSObject
{
    xpc_object_t _systemInfoXdict;
    struct rh_credential_snapshot _bootstrapCredentialSnapshot;
    BOOL _bootstrapIdentityActive;
}

- (void)runWithError:(NSError **)errOut didRemoveJailbreak:(BOOL*)didRemove showLogs:(BOOL *)showLogs;
- (void)finalize;

- (BOOL)contiguousMappingWorkaroundNeeded;
- (void)applyContiguousMappingWorkaround;

@end

NS_ASSUME_NONNULL_END
