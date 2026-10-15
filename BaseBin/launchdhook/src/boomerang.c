#include <spawn.h>
#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/jbserver.h>
#include <libjailbreak/jbserver_boomerang.h>
#include <libjailbreak/physrw.h>
#include <libjailbreak/physrw_pte.h>
#include <libjailbreak/primitives_IOSurface.h>
#include <libjailbreak/kcall_Fugu14.h>
#include <libjailbreak/kcall_arm64.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <signal.h>

int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *__restrict attr, mach_port_t portarray[], uint32_t count);

#define JB_DOMAIN_PRIMITIVE_STORAGE 10

#define JB_PRIMITIVE_STORAGE_RETRIEVE_PHYSRW 1
#define JB_PRIMITIVE_STORAGE_RETRIEVE_KCALL 2

static void terminateFailedBoomerang(pid_t pid)
{
	if (pid <= 1) return;
	int status = 0;
	pid_t waited;
	do {
		waited = waitpid(pid, &status, WNOHANG);
	} while (waited == -1 && errno == EINTR);
	// A reaped child, or ECHILD, must never turn into a signal to a reused PID.
	if (waited != 0) return;
	int result;
	do {
		result = kill(pid, SIGKILL);
	} while (result == -1 && errno == EINTR);
	if (result != 0 && errno != ESRCH) {
		JBLogError("failed to terminate boomerang pid=%d errno=%d", pid, errno);
	}
	do {
		waited = waitpid(pid, &status, WNOHANG);
	} while (waited == -1 && errno == EINTR);
	// launchd's SIGCHLD handling reaps the child if SIGKILL is still pending.
}

int boomerang_stashPrimitives(void)
{
	__block bool handoffComplete = false;
	dispatch_semaphore_t boomerangDone = dispatch_semaphore_create(0);
	dispatch_semaphore_t serverStopped = dispatch_semaphore_create(0);
	dispatch_queue_t serverQueue = dispatch_queue_create("com.roothide.reboot-handoff", DISPATCH_QUEUE_SERIAL);
	mach_port_t serverPort = MACH_PORT_NULL;
	int result = ENOMEM;
	if (!boomerangDone || !serverStopped || !serverQueue) goto setup_failed;
	result = EIO;
	if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort) != KERN_SUCCESS) goto setup_failed;
	if (mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) goto setup_failed;

	// This hook can wait on launchd's main queue. Receive the helper's RPCs
	// independently so that the wait cannot prevent their execution.
	dispatch_source_t serverSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)serverPort, 0, serverQueue);
	result = ENOMEM;
	if (!serverSource) goto setup_failed;
	// The source keeps its own semaphore references until cancellation drains
	// its handlers, including when this function returns after a timeout.
	dispatch_retain(boomerangDone);
	dispatch_retain(serverStopped);
	dispatch_source_set_event_handler(serverSource, ^{
		if (handoffComplete) return;
		xpc_object_t xdict = NULL;
		if (!xpc_pipe_receive(serverPort, &xdict) && xdict) {
			if (jbserver_received_boomerang_xpc_message(&gBoomerangServer, xdict) == JBS_BOOMERANG_DONE) {
				handoffComplete = true;
				dispatch_semaphore_signal(boomerangDone);
			}
		}
		if (xdict) xpc_release(xdict);
	});
	dispatch_source_set_cancel_handler(serverSource, ^{
		mach_port_destroy(mach_task_self(), serverPort);
		dispatch_semaphore_signal(serverStopped);
		dispatch_release(boomerangDone);
		dispatch_release(serverStopped);
	});
	dispatch_resume(serverSource);
	dispatch_release(serverQueue);

	// Spawn boomerang process
	pid_t boomerangPid = 0;
	posix_spawnattr_t attr = NULL;
	result = posix_spawnattr_init(&attr);
	if (result == 0) {
		result = posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){ MACH_PORT_NULL, MACH_PORT_NULL, serverPort }, 3);
		if (result == 0) {
			const char *path = JBROOT_PATH("/basebin/boomerang");
			char *argv[] = { (char *)path, NULL };
			char *envp[] = { NULL };
			result = posix_spawn(&boomerangPid, path, NULL, &attr, argv, envp);
		}
		posix_spawnattr_destroy(&attr);
	}

	if (result == 0) {
		result = ETIMEDOUT;
		for (unsigned attempt = 0; attempt < 300; attempt++) {
			if (dispatch_semaphore_wait(boomerangDone, dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC)) == 0) {
				result = 0;
				break;
			}
			int status = 0;
			pid_t waited = waitpid(boomerangPid, &status, WNOHANG);
			if (waited == boomerangPid || (waited == -1 && errno == ECHILD)) {
				boomerangPid = 0;
				result = EIO;
				break;
			}
			if (waited == -1 && errno != EINTR) {
				result = errno;
				break;
			}
		}
	}
	if (result != 0) terminateFailedBoomerang(boomerangPid);
	dispatch_source_cancel(serverSource);
	// Cancellation owns port destruction. A slow in-flight handler must not
	// cause a second infinite wait or use a prematurely destroyed receive right.
	if (dispatch_semaphore_wait(serverStopped, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC)) != 0 && result == 0) {
		result = ETIMEDOUT;
		terminateFailedBoomerang(boomerangPid);
	}
	dispatch_release(serverSource);
	dispatch_release(boomerangDone);
	dispatch_release(serverStopped);
	if (result != 0) return result;

	// Stash boomerang pid in environment to later be able to call waitpid on it
	char pidBuf[32];
	snprintf(pidBuf, sizeof(pidBuf), "%d", boomerangPid);
	if (setenv("BOOMERANG_PID", pidBuf, 1) != 0) {
		int environmentError = errno;
		terminateFailedBoomerang(boomerangPid);
		return environmentError ? environmentError : EIO;
	}
	return 0;

setup_failed:
	if (MACH_PORT_VALID(serverPort)) mach_port_destroy(mach_task_self(), serverPort);
	if (serverQueue) dispatch_release(serverQueue);
	if (boomerangDone) dispatch_release(boomerangDone);
	if (serverStopped) dispatch_release(serverStopped);
	return result;
}

int boomerang_recoverPrimitives(bool firstRetrieval, bool shouldEndBoomerang)
{
	// Mach port to boomerang should be stored in our registeredPorts[2]
	// Use it to recover primitives, afterwards replace it with MACH_PORT_NULL to make launchd happy
	mach_port_t *registeredPorts = NULL;
	mach_msg_type_number_t registeredPortsCount = 0;
	if (mach_ports_lookup(mach_task_self(), &registeredPorts, &registeredPortsCount) != 0 || registeredPortsCount < 3) return -1;
	mach_port_t boomerangPort = registeredPorts[2];
	if (!MACH_PORT_VALID(boomerangPort)) return -2;
	jbclient_xpc_set_custom_port(boomerangPort);
	registeredPorts[2] = MACH_PORT_NULL;
	int result = mach_ports_register(mach_task_self(), registeredPorts, registeredPortsCount);
	if (result != KERN_SUCCESS) return result;

	// Retrieve primitives
	// For performance reasons we only use physrw_pte until the first userspace reboot
	// Handing off full physrw from the app is really slow and causes watchdog timeouts
	// But from launchd it's generally fine, no clue why
	bool physrwPTE = firstRetrieval && !is_kcall_available();
	result = jbclient_initialize_primitives_internal(physrwPTE);
	if (result != 0) return result;

	if (shouldEndBoomerang) {
		// Send done message to boomerang
		result = jbclient_boomerang_done();
		if (result != 0) return result;

		// Keep the helper identity until recovery and DONE both succeed. Only
		// a complete, positive PID is safe for launchd's child cleanup.
		pid_t boomerangPid = 0;
		const char *pidBuf = getenv("BOOMERANG_PID");
		if (pidBuf) {
			char *end = NULL;
			errno = 0;
			long parsedPid = strtol(pidBuf, &end, 10);
			if (errno == 0 && pidBuf[0] >= '0' && pidBuf[0] <= '9' &&
			    end && *end == '\0' && parsedPid > 1 && parsedPid <= INT_MAX) {
				boomerangPid = (pid_t)parsedPid;
			}
			unsetenv("BOOMERANG_PID");
		}

		// Remove boomerang zombie proc if needed
		if (boomerangPid > 1) {
			int boomerangStatus = 0;
			pid_t waited;
			do {
				// launchd reaps SIGCHLD if the helper has not exited yet.
				waited = waitpid(boomerangPid, &boomerangStatus, WNOHANG);
			} while (waited == -1 && errno == EINTR);
			if (waited == -1 && errno != ECHILD) {
				JBLogError("failed to reap boomerang pid=%d errno=%d", boomerangPid, errno);
			}
		}
	}

	return 0;
}
