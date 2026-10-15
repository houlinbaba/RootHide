#ifndef RH_USERSPACE_REBOOT_H
#define RH_USERSPACE_REBOOT_H

#include <sys/types.h>

struct rh_userspace_reboot {
    pid_t pid;
    int releaseFD;
};

#define RH_USERSPACE_REBOOT_EMPTY ((struct rh_userspace_reboot){ .pid = -1, .releaseFD = -1 })

// Caller serializes ownership. Prepare with bootstrap root, then restore the
// App's original mobile credential before finish authorizes the child.
int rh_userspace_reboot_prepare(struct rh_userspace_reboot *request, const char *jbctl, char *const env[]);
int rh_userspace_reboot_finish(struct rh_userspace_reboot *request);
int rh_userspace_reboot_cancel(struct rh_userspace_reboot *request);

#endif
