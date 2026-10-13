#include "jbclient_xpc.h"
#include "info.h"
#include "roothide_stage.h"
#include <errno.h>
#include <sandbox.h>
#include <stdlib.h>
#include <string.h>

// App-owned system_info is linked by libjailbreak. Keep this wrapper out of
// jbclient_*.c: systemhook also compiles those clients, without info.c.
int jbclient_app_checkin(void)
{
	char *rootPath = NULL, *extensions = NULL;
	int result = jbclient_process_checkin(&rootPath, NULL, &extensions, NULL, NULL);
	unsigned consumed = 0;
	if (result != 0) goto done;
	if (!rootPath || rootPath[0] != '/' || !extensions || !*extensions) {
		result = EPROTO;
		goto done;
	}
	if (jbinfo(rootPath) && strcmp(jbinfo(rootPath), rootPath)) {
		result = ESTALE;
		goto done;
	}
	// Keep the grants for the lifetime of this process, as dyldhook does.
	// Never log the token contents. The check-in fallback must consume every
	// grant even when systemhook was not injected into the certificate App.
	char *token = extensions;
	while (token) {
		char *next = strchr(token, '|');
		if (next) *next++ = '\0';
		if (!*token) { result = EPROTO; goto done; }
		errno = 0;
		if (sandbox_extension_consume(token) < 0) {
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
done:
	roothide_stage_log("app.checkin.grants result=%d consumed=%u root_cached=%d",
	                   result, consumed, jbinfo(rootPath) != NULL);
	free(rootPath);
	free(extensions);
	return result;
}
