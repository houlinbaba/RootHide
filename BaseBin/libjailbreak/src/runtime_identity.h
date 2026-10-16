#ifndef RH_RUNTIME_IDENTITY_H
#define RH_RUNTIME_IDENTITY_H
#include <stdbool.h>

// Own-process mapped code only. Output contains no address or path.
bool rh_image_uuid_for_address(const void *implementation, char out[37]);

enum rh_runtime_identity_status {
    RH_RUNTIME_REPORTED = 0, // Well-formed attribution, NOT verified build/READY.
    RH_RUNTIME_UNSUPPORTED,
    RH_RUNTIME_MALFORMED,
    RH_RUNTIME_UNKNOWN_IMAGE,
    RH_RUNTIME_NO_REPLY,
};
struct rh_runtime_identity {
    bool first_load;
    char handler_uuid[37], credential_uuid[37];
};
// Synchronous transport; callers must use a worker and retain its resources
// until return. A local waiting deadline does not cancel this operation.
enum rh_runtime_identity_status jbclient_dopamine_runtime_identity(struct rh_runtime_identity *out);
// Requires an independently obtained, architecture-specific build manifest.
bool rh_runtime_identity_matches(const struct rh_runtime_identity *reported,
                               const char *handler_uuid, const char *credential_uuid);
#endif
