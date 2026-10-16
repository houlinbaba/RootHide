#include "jbserver_global.h"
#include "jbsettings.h"

#include <libjailbreak/codesign.h>
#include <libjailbreak/libjailbreak.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <libjailbreak/credentials.h>
#include <libjailbreak/runtime_identity.h>
#include <stdatomic.h>
#include <errno.h>

static char *read_file_to_string(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    long size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return NULL;
    }
    rewind(fp);

    char *buffer = malloc((size_t)size + 1);
    if (!buffer) {
        fclose(fp);
        return NULL;
    }

    size_t read_bytes = fread(buffer, 1, (size_t)size, fp);
    fclose(fp);

    if (read_bytes != (size_t)size) {
        free(buffer);
        return NULL;
    }

    buffer[size] = '\0';
    return buffer;
}

bool dopamine_domain_allowed(audit_token_t clientToken)
{
	char path[PATH_MAX];
	struct rh_failure_scope scope;
	rh_failure_begin(&scope, "dopamine_authorize", audit_token_to_pid(clientToken));
	int pathResult = proc_pidpath_audittoken(&clientToken, path, PATH_MAX);
	if (pathResult <= 0) {
		rh_failure_end(&scope, "authorize_path", "libproc_return", pathResult, -2);
		return false;
	}
	bool allowed = is_dopamine_app(path);
	rh_failure_end(&scope, "authorize_bundle", "policy_bool", allowed, allowed ? 0 : -2);
	return allowed;
}

static _Atomic int runtimeFirstLoad; // 0 unknown; 1 first load; 2 subsequent load

void dopamine_runtime_identity_set_first_load(bool firstLoad)
{
	atomic_store_explicit(&runtimeFirstLoad, firstLoad ? 1 : 2, memory_order_release);
}

int dopamine_is_jailbroken(char **outVersion, xpc_object_t *outRuntimeIdentity)
{
	*outVersion = read_file_to_string(JBROOT_PATH("/basebin/.version"));
	// Optional second output preserves action 1's existing bool result/version.
	// Both implementation pointers resolve in this server process, not the App.
	xpc_object_t metadata = xpc_dictionary_create_empty();
	if (metadata) {
		xpc_dictionary_set_uint64(metadata, "format", 1);
		int phase = atomic_load_explicit(&runtimeFirstLoad, memory_order_acquire);
		if (phase) xpc_dictionary_set_bool(metadata, "first-load", phase == 1);
		char uuid[37];
		if (rh_image_uuid_for_address((const void *)dopamine_is_jailbroken, uuid))
			xpc_dictionary_set_string(metadata, "handler-uuid", uuid);
		if (rh_image_uuid_for_address((const void *)proc_credential_restore_self, uuid))
			xpc_dictionary_set_string(metadata, "credential-uuid", uuid);
	}
	*outRuntimeIdentity = metadata; // dispatcher owns/releases this +1 reference
	return 1; // Existing wire result, now explicitly matches dispatcher's int ABI.
}

int dopamine_get_root(audit_token_t *processToken)
{
	pid_t pid = audit_token_to_pid(*processToken);
	struct rh_failure_scope scope;
	rh_failure_begin(&scope, "get_root", pid);
	uint64_t proc = proc_find(pid);
	if (!proc) return rh_failure_end(&scope, "find_target", "lookup_bool", 0, 1);
	if (__builtin_available(iOS 17.0, *)) {
		struct rh_credential identity;
		int r = proc_credential_read(proc, &identity);
		if (r) return rh_failure_end(&scope, "pre_read", "credential_status", r, r);
		if (identity.uid != 501) return rh_failure_end(&scope, "validate_identity", "policy_status", EPERM, EPERM);
		char path[PROC_PIDPATHINFO_MAXSIZE];
		int pathResult = proc_pidpath_audittoken(processToken, path, sizeof(path));
		if (pathResult <= 0) return rh_failure_end(&scope, "target_path", "libproc_return", pathResult, ESRCH);
		identity.uid = 0;
		identity.gid = identity.groups[0] = 0;
		r = proc_credential_set(proc, path, &identity);
		return rh_failure_end(&scope, "install", "credential_status", r, r);
	}
	uint64_t ucred = proc_ucred(proc);

	if (kread32(ucred + koffsetof(ucred, uid)) == 501) {
		kwrite32(ucred + koffsetof(ucred, uid), 0);
		kwrite32(ucred + koffsetof(ucred, groups), 0);

		if (gSystemInfo.kernelStruct.proc_ro.exists) {
			uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));

			if (koffsetof(proc_ro, task_tokens)) {
				uint64_t auditToken = proc_ro + koffsetof(proc_ro, task_tokens) + koffsetof(task_token_ro_data, audit_token);
				kwrite32(auditToken + 4, 0); // uid
				kwrite32(auditToken + 8, 0); // gid
			}
		}

		return rh_failure_end(&scope, "legacy_install", "legacy_status", 0, 0);
	}

	return rh_failure_end(&scope, "legacy_identity", "legacy_status", 1, 1);
}

int dopamine_drop_root(audit_token_t *processToken)
{
	pid_t pid = audit_token_to_pid(*processToken);
	struct rh_failure_scope scope;
	rh_failure_begin(&scope, "drop_root", pid);
	uint64_t proc = proc_find(pid);
	if (!proc) return rh_failure_end(&scope, "find_target", "lookup_bool", 0, 1);
	if (__builtin_available(iOS 17.0, *)) {
		struct rh_credential identity;
		int r = proc_credential_read(proc, &identity);
		if (r) return rh_failure_end(&scope, "pre_read", "credential_status", r, r);
		if (identity.uid != 0) return rh_failure_end(&scope, "validate_identity", "policy_status", EPERM, EPERM);
		char path[PROC_PIDPATHINFO_MAXSIZE];
		int pathResult = proc_pidpath_audittoken(processToken, path, sizeof(path));
		if (pathResult <= 0) return rh_failure_end(&scope, "target_path", "libproc_return", pathResult, ESRCH);
		identity.uid = 501;
		identity.gid = identity.groups[0] = 501;
		r = proc_credential_set(proc, path, &identity);
		return rh_failure_end(&scope, "install", "credential_status", r, r);
	}
	uint64_t ucred = proc_ucred(proc);

	if (kread32(ucred + koffsetof(ucred, uid)) == 0) {
		kwrite32(ucred + koffsetof(ucred, uid), 501);
		kwrite32(ucred + koffsetof(ucred, groups), 501);

		if (gSystemInfo.kernelStruct.proc_ro.exists) {
			uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));

			if (koffsetof(proc_ro, task_tokens)) {
				uint64_t auditToken = proc_ro + koffsetof(proc_ro, task_tokens) + koffsetof(task_token_ro_data, audit_token);
				kwrite32(auditToken + 4, 501); // uid
				kwrite32(auditToken + 8, 501); // gid
			}
		}

		return rh_failure_end(&scope, "legacy_install", "legacy_status", 0, 0);
	}

	return rh_failure_end(&scope, "legacy_identity", "legacy_status", 1, 1);
}

struct jbserver_domain gDopamineDomain = {
	.permissionHandler = dopamine_domain_allowed,
	.actions = {
		// JBS_DOPAMINE_IS_JAILBROKEN
		{
			.handler = dopamine_is_jailbroken,
			.args = (jbserver_arg[]){
				{ .name = "version", .type = JBS_TYPE_STRING, .out = true },
				{ .name = "runtime-identity", .type = JBS_TYPE_DICTIONARY, .out = true },
				{ 0 },
			},
		},
		// JBS_DOPAMINE_GET_ROOT
		{
			.handler = dopamine_get_root,
			.args = (jbserver_arg[]){
				{ .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
				{ 0 },
			},
		},
		// JBS_DOPAMINE_DROP_ROOT
		{
			.handler = dopamine_drop_root,
			.args = (jbserver_arg[]){
				{ .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
				{ 0 },
			},
		},
		{ 0 },
	},
};
