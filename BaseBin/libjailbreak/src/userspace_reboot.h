#ifndef RH_USERSPACE_REBOOT_H
#define RH_USERSPACE_REBOOT_H

#include <sys/types.h>

struct rh_userspace_reboot {
    pid_t pid;
    int releaseFD;
};

#define RH_USERSPACE_REBOOT_EMPTY ((struct rh_userspace_reboot){ .pid = -1, .releaseFD = -1 })

// Prepare while bootstrap still owns root credentials. The child cannot act
// until finish sends the token, after the App has restored its original ucred.
int rh_userspace_reboot_prepare(struct rh_userspace_reboot *request, const char *jbctl, char *const env[]);
int rh_userspace_reboot_finish(struct rh_userspace_reboot *request);
int rh_userspace_reboot_cancel(struct rh_userspace_reboot *request);
// Shared by jbctl's --waitfor path: EOF, invalid tokens and timeout cancel.
int rh_userspace_reboot_wait(int fd);

#endif
