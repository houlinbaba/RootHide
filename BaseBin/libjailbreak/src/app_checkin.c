#include "jbclient_xpc.h"
#include "info.h"
#include "roothide_stage.h"
#include <errno.h>
#include <sandbox.h>
#include <stdlib.h>
#include <string.h>

// systemhook also compiles jbclient_*.c without info.c. Keep App state here.
int jbclient_app_checkin(void)
{
	char *rootPath = NULL, *extensions = NULL;
	int result = jbclient_process_checkin(&rootPath, NULL, &extensions, NULL, NULL);
	int rpcResult = result, consumeErrno = 0;
	const char *phase = "rpc";
	unsigned consumed = 0;
	if (result != 0) goto done;
	phase = "reply_fields";
	if (!rootPath || rootPath[0] != '/' || !extensions || !*extensions) {
		result = EPROTO;
		goto done;
	}
	phase = "root_match";
	if (jbinfo(rootPath) && strcmp(jbinfo(rootPath), rootPath)) {
		result = ESTALE;
		goto done;
	}
	// As in dyldhook, retain successful grants for the process lifetime.
	// An App launched without systemhook must consume the grants itself.
	char *token = extensions;
	while (token) {
		phase = "grant_format";
		char *next = strchr(token, '|');
		if (next) *next++ = '\0';
		if (!*token) { result = EPROTO; goto done; }
		errno = 0;
		phase = "grant_consume";
		if (sandbox_extension_consume(token) < 0) {
			consumeErrno = errno;
			result = errno ?: EACCES;
			goto done;
		}
		consumed++;
		token = next;
	}
	if (!jbinfo(rootPath)) {
		jbinfo(rootPath) = rootPath;
		rootPath = NULL;
	}
	phase = "complete";
done:
	roothide_stage_log("app.checkin.outcome phase=%s rpc_result=%d consume_errno=%d result=%d consumed=%u",
	                   phase, rpcResult, consumeErrno, result, consumed);
	roothide_stage_log("app.checkin.grants result=%d consumed=%u root_cached=%d",
	                   result, consumed, jbinfo(rootPath) != NULL);
	free(rootPath);
	free(extensions);
	return result;
}
