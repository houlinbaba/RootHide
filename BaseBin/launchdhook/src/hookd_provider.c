#include "hookd_provider.h"

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/hookd.h>
#include <libjailbreak/inline_svc.h>
#include <spawn.h>
#include <signal.h>
#include <errno.h>

pid_t gHookdPid = -1;
mach_port_t gHookdPort = MACH_PORT_NULL;
int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t * __restrict attr, mach_port_t portarray[], uint32_t count);

int hookd_start(pid_t *pid, mach_port_t *machPort)
{
	if (!pid || !machPort) return EINVAL;

	*machPort = MACH_PORT_NULL;
	mach_port_t checkinPort = MACH_PORT_NULL;
	kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &checkinPort);
	if (kr != KERN_SUCCESS) return kr;

	kr = mach_port_insert_right(mach_task_self(), checkinPort, checkinPort, MACH_MSG_TYPE_MAKE_SEND);
	if (kr != KERN_SUCCESS) {
		mach_port_destroy(mach_task_self(), checkinPort);
		return kr;
	}

	posix_spawnattr_t attr;
	int r = posix_spawnattr_init(&attr);
	if (r != 0) {
		mach_port_destroy(mach_task_self(), checkinPort);
		return r;
	}
	r = posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){MACH_PORT_NULL, MACH_PORT_NULL, checkinPort}, 3);
	if (r != 0) {
		posix_spawnattr_destroy(&attr);
		mach_port_destroy(mach_task_self(), checkinPort);
		return r;
	}

	const char *envp[] = {
		"_SafeMode=1",
		NULL,
	};

	const char *path = JBROOT_PATH("/basebin/hookd");
	r = posix_spawn(pid, path, NULL, &attr, (char *[]){ (char *)path, NULL }, (char *const *)envp);
	posix_spawnattr_destroy(&attr);
	if (r != 0) {
		mach_port_destroy(mach_task_self(), checkinPort);
		return r;
	}

	// Mach receive writes a trailer after the header, even for a header-only message.
	// The previous buffer only contained a header but advertised room for a trailer.
	struct {
		mach_msg_header_t hdr;
		uint8_t trailer[MAX_TRAILER_SIZE];
	} checkinMsg = {0};
	kr = mach_msg(&checkinMsg.hdr, MACH_RCV_MSG, 0, sizeof(checkinMsg), checkinPort, 0, 0);
	mach_port_destroy(mach_task_self(), checkinPort);
	if (kr != KERN_SUCCESS) {
		// The spawned helper cannot complete check-in; do not leave it running.
		kill(*pid, SIGKILL);
		return kr;
	}

	mach_port_t receivedPort = checkinMsg.hdr.msgh_remote_port;
	if (!MACH_PORT_VALID(receivedPort)) {
		mach_msg_destroy(&checkinMsg.hdr);
		kill(*pid, SIGKILL);
		return KERN_INVALID_RIGHT;
	}

	kr = mach_port_mod_refs(mach_task_self(), receivedPort, MACH_PORT_RIGHT_SEND, 1);
	mach_msg_destroy(&checkinMsg.hdr);
	if (kr != KERN_SUCCESS) {
		kill(*pid, SIGKILL);
		return kr;
	}

	*machPort = receivedPort;
	return 0;
}

static int launchd_hookd_send_msg(struct hookd_mach_msg *msg, struct hookd_mach_msg_reply *reply)
{
	int wpr = -1;
	if (gHookdPid != -1) {
		int status = 0;
		// Call waitpid as inline syscall to prevent crashes when something tries to hook something close to wait4
		wpr = waitpid_inline(gHookdPid, &status, WNOHANG);
	}	

	if (wpr != 0) {
		int sr = hookd_start(&gHookdPid, &gHookdPort);
		if (sr != 0) return sr;
	}

	mach_port_t replyPort = mig_get_reply_port();

	msg->hdr.msgh_bits        |= MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
	msg->hdr.msgh_remote_port  = gHookdPort;
	msg->hdr.msgh_local_port   = replyPort;
	msg->hdr.msgh_voucher_port = 0;
	msg->hdr.msgh_id           = 0x40000000;

	kern_return_t kr = mach_msg(&msg->hdr, MACH_SEND_MSG, msg->hdr.msgh_size, 0, 0, 0, 0);
	if (kr != KERN_SUCCESS) return kr;
	
	kr = mach_msg(&reply->hdr, MACH_RCV_MSG, 0, reply->hdr.msgh_size, replyPort, 0, 0);
	if (kr != KERN_SUCCESS) return kr;

	mach_msg_destroy(&reply->hdr);
	return 0;
}

void hookd_provider_init(void)
{
	hookd_send_msg = launchd_hookd_send_msg;
}

void hookd_provider_teardown(void)
{
	hookd_send_msg = NULL;
	if (gHookdPid != -1) {
		int status = 0;
		if (waitpid(gHookdPid, &status, WNOHANG) == 0) {
			kill(gHookdPid, SIGKILL);
			cmd_wait_for_exit(gHookdPid);
		}
	}
}