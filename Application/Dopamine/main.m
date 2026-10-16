//
//  main.m
//  Dopamine
//
//  Created by Lars Fröder on 23.09.23.
//

#import <UIKit/UIKit.h>
#import "DOAppDelegate.h"

#import "DOEnvironmentManager.h"
#import <libjailbreak/info.h>
#import <libjailbreak/jbclient_xpc.h>
#import <libjailbreak/roothide_stage.h>
#import <libjailbreak/codesign.h>
#import "DOUIManager.h"
#include <unistd.h>
#include <errno.h>

static long credential_helper_syscall(int number, uintptr_t a, uintptr_t b, uintptr_t c)
{
    long r = syscall(number, a, b, c);
    return r < 0 ? -errno : r;
}
#define RH_CREDENTIAL_SYSCALL(number, a, b, c) credential_helper_syscall(number, (uintptr_t)(a), (uintptr_t)(b), (uintptr_t)(c))
#include <libjailbreak/credential_helper.h>

int main(int argc, char * argv[]) {
    // Bootstrap donors use the signed App and the original dyld. Finish before
    // the environment manager, server check-in or UIKit can run.
    if (rh_credential_helper_main(argc, argv)) return 0;
    if (argc >= 3) {
        if (!strcmp(argv[1], "trollstore")) {
            if (!strcmp(argv[2], "delete-bootstrap")) {
                [[DOEnvironmentManager sharedManager] deleteBootstrap];
            }
/*
            else if (!strcmp(argv[2], "hide-jailbreak")) {
                [[DOEnvironmentManager sharedManager] setJailbreakHidden:YES];
            }
*/
            return 0;
        }
    }
    
    if (argc >= 2) {
        // Legacy, called by Dopamine 1.x before initiating a jbupdate
        // As updating from 1.x to 2.x is unsupported, just initiate a device reboot
        if (!strcmp(argv[1], "prepare_jbupdate")) {
            [[DOEnvironmentManager sharedManager] reboot];
            return 0;
        }
    }
    
    // If systemhook isn't loaded and we are already jailbroken, we need to do the checkin ourselves
    // This can happen when the jailbreak is hidden or when tweak injection into the Dopamine app is disabled via Choicy
    @autoreleasepool {
        int logResult = roothide_stage_begin([[DOUIManager sharedInstance] rootHideStageLogPath].fileSystemRepresentation, true);
        const char *build = "release";
#ifdef NIGHTLY
        build = COMMIT_HASH;
#endif
        roothide_stage_log("app.launch.begin build=%s log_open_result=%d uid=%u euid=%u gid=%u egid=%u",
                           build, logResult, (unsigned)getuid(), (unsigned)geteuid(),
                           (unsigned)getgid(), (unsigned)getegid());
        int checkinResult = jbclient_app_checkin();
        uint32_t flags = 0;
        int flagsResult = csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags));
        BOOL active = [DOEnvironmentManager sharedManager].isJailbroken;
        roothide_stage_log("app.launch.end checkin_result=%d active_session=%d csops_result=%d platform=%d root_cached=%d uid=%u euid=%u",
                           checkinResult, active, flagsResult, (flags & CS_PLATFORM_BINARY) != 0,
                           jbinfo(rootPath) != NULL, (unsigned)getuid(), (unsigned)geteuid());
        roothide_stage_end();
    }
    
    if ([DOEnvironmentManager sharedManager].isJailbroken) {
        setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin:/rootfs/sbin:/rootfs/bin:/rootfs/usr/sbin:/rootfs/usr/bin", 1);
        setenv("TERM", "xterm-256color", 1);
    }
    
    NSString * appDelegateClassName;
    @autoreleasepool {
        // Setup code that might create autoreleased objects goes here.
        appDelegateClassName = NSStringFromClass([DOAppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
