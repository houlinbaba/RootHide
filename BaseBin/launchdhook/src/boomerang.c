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
#include <sys/wait.h>
#include <signal.h>

int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *__restrict attr, mach_port_t portarray[], uint32_t count);

#define JB_DOMAIN_PRIMITIVE_STORAGE 10

#define JB_PRIMITIVE_STORAGE_RETRIEVE_PHYSRW 1
#define JB_PRIMITIVE_STORAGE_RETRIEVE_KCALL 2

int boomerang_stashPrimitives()
{
	dispatch_semaphore_t boomerangDone = dispatch_semaphore_create(0);
	dispatch_semaphore_t serverStopped = dispatch_semaphore_create(0);
	// launchd can execute this hook on its main queue. Its synchronous wait
	// must not prevent the primitive server from receiving boomerang's RPCs.
	dispatch_queue_t serverQueue = dispatch_queue_create("com.roothide.reboot-handoff", DISPATCH_QUEUE_SERIAL);
	if (!boomerangDone || !serverStopped || !serverQueue) return ENOMEM;

	mach_port_t serverPort = MACH_PORT_NULL;
	kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort);
	if (kr != KERN_SUCCESS) return EIO;
	kr = mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND);
	if (kr != KERN_SUCCESS) {
		mach_port_destroy(mach_task_self(), serverPort);
		return EIO;
	}

	// Small server provided to boomerang to obtain exploit primitives
	dispatch_source_t serverSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)serverPort, 0, serverQueue);
	if (!serverSource) {
		mach_port_destroy(mach_task_self(), serverPort);
		return ENOMEM;
	}
	__block bool handoffComplete = false;
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
		// No in-flight handler may still be using this receive right.
		mach_port_destroy(mach_task_self(), serverPort);
		dispatch_semaphore_signal(serverStopped);
	});
	dispatch_resume(serverSource);

	// Spawn boomerang process
	pid_t boomerangPid = 0;
	posix_spawnattr_t attr = NULL;
	int result = posix_spawnattr_init(&attr);
	if (result == 0) {
		result = posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){ MACH_PORT_NULL, MACH_PORT_NULL, serverPort }, 3);
		if (result == 0) {
			const char *path = JBROOT_PATH("/basebin/boomerang");
			// Never inject launchdhook into the helper by inheriting launchd's environment.
			char *argv[] = { (char *)path, NULL };
			char *envp[] = { NULL };
			result = posix_spawn(&boomerangPid, path, NULL, &attr, argv, envp);
		}
		posix_spawnattr_destroy(&attr);
	}

	// Observe a failed helper rather than waiting forever for a DONE it cannot send.
	if (result == 0) {
		result = ETIMEDOUT;
		for (unsigned attempt = 0; attempt < 300; attempt++) {
			if (dispatch_semaphore_wait(boomerangDone, dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC)) == 0) {
				result = 0;
				break;
			}
			int status = 0;
			pid_t waited = waitpid(boomerangPid, &status, WNOHANG);
			if (waited == boomerangPid || (waited < 0 && errno != EINTR)) {
				result = EIO;
				boomerangPid = 0; // Reaped, or no longer our child: do not signal a reused PID.
				break;
			}
		}
	}
	dispatch_source_cancel(serverSource);
	dispatch_semaphore_wait(serverStopped, DISPATCH_TIME_FOREVER);
	if (result != 0) {
		if (boomerangPid > 1) {
			kill(boomerangPid, SIGKILL);
			waitpid(boomerangPid, NULL, WNOHANG);
		}
		return result;
	}

	// Stash boomerang pid in environment to later be able to call waitpid on it
	char pidBuf[32];
	snprintf(pidBuf, sizeof(pidBuf), "%d", boomerangPid);
	if (setenv("BOOMERANG_PID", pidBuf, 1) != 0) {
		int environmentError = errno ?: EIO;
		kill(boomerangPid, SIGKILL);
		waitpid(boomerangPid, NULL, WNOHANG);
		return environmentError;
	}
	return 0;
}

int boomerang_recoverPrimitives(bool firstRetrieval, bool shouldEndBoomerang)
{
	// Mach port to boomerang should be stored in our registeredPorts[2]
	// Use it to recover primitives, afterwards replace it with MACH_PORT_NULL to make launchd happy
	mach_port_t *registeredPorts;
	mach_msg_type_number_t registeredPortsCount = 0;
	if (mach_ports_lookup(mach_task_self(), &registeredPorts, &registeredPortsCount) != 0 || registeredPortsCount < 3) return -1;
	mach_port_t boomerangPort = registeredPorts[2];
	if (boomerangPort == MACH_PORT_NULL) return -2;
	jbclient_xpc_set_custom_port(boomerangPort);
	registeredPorts[2] = MACH_PORT_NULL;
	mach_ports_register(mach_task_self(), registeredPorts, registeredPortsCount);

	// Recover boomerang pid from environment
	pid_t boomerangPid = 0;
	const char *pidBuf = getenv("BOOMERANG_PID");
	if (pidBuf) {
		boomerangPid = atoi(pidBuf);
		unsetenv("BOOMERANG_PID");
	}

	// Retrieve primitives
	// For performance reasons we only use physrw_pte until the first userspace reboot
	// Handing off full physrw from the app is really slow and causes watchdog timeouts
	// But from launchd it's generally fine, no clue why
	bool physrwPTE = firstRetrieval && !is_kcall_available();
	int result = jbclient_initialize_primitives_internal(physrwPTE);
	if (result != 0) return result;

	if (shouldEndBoomerang) {
		// Send done message to boomerang
		result = jbclient_boomerang_done();
		if (result != 0) return result;

		// Remove boomerang zombie proc if needed
		if (boomerangPid != 0) {
			int boomerangStatus;
			// DONE already made the helper exit. Never block launchd initialization
			// on a child that has not reached exit yet; launchd reaps SIGCHLD.
			waitpid(boomerangPid, &boomerangStatus, WNOHANG);
		}
	}

	return 0;
}
