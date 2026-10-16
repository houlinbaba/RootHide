#include "runtime_identity.h"
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#include <stdint.h>
#include <string.h>
#include <uuid/uuid.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

bool rh_image_uuid_for_address(const void *implementation, char out[37])
{
    if (!out) return false;
    out[0] = 0;
    if (!implementation) return false;
#if __has_feature(ptrauth_calls)
    implementation = ptrauth_strip(implementation, ptrauth_key_function_pointer);
#endif
    Dl_info info = {0};
    if (!dladdr(implementation, &info) || !info.dli_fbase) return false;
    const struct mach_header_64 *header = info.dli_fbase;
    if (header->magic != MH_MAGIC_64 || header->sizeofcmds > 1024 * 1024) return false;
    const unsigned char *cursor = (const unsigned char *)(header + 1);
    size_t remaining = header->sizeofcmds;
    const struct uuid_command *uuid = NULL;
    const struct segment_command_64 *text = NULL;
    // Find the segment containing the mapped header; derive slide without
    // filename assumptions or walking/reopening files on disk.
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (remaining < sizeof(struct load_command)) return false;
        const struct load_command *lc = (const void *)cursor;
        if (lc->cmdsize < sizeof(*lc) || lc->cmdsize > remaining || (lc->cmdsize & 7)) return false;
        if (lc->cmd == LC_UUID) {
            if (lc->cmdsize != sizeof(struct uuid_command) || uuid) return false;
            uuid = (const void *)lc;
        }
        if (lc->cmd == LC_SEGMENT_64) {
            if (lc->cmdsize < sizeof(struct segment_command_64)) return false;
            const struct segment_command_64 *segment = (const void *)lc;
            if (!segment->fileoff && segment->filesize >= sizeof(*header) + (uint64_t)header->sizeofcmds
                && (segment->initprot & VM_PROT_EXECUTE)) {
                if (text) return false;
                text = segment;
            }
        }
        cursor += lc->cmdsize;
        remaining -= lc->cmdsize;
    }
    if (remaining || !uuid || !text || uuid_is_null(uuid->uuid)) return false;
    uintptr_t base = (uintptr_t)header, address = (uintptr_t)implementation;
    // Require actual code membership in this executable header segment.
    // Unsupported layouts are unknown, never guessed from a basename.
    if (address < base || address - base >= text->vmsize) return false;
    uuid_unparse_upper(uuid->uuid, out);
    return true;
}

bool rh_runtime_identity_matches(const struct rh_runtime_identity *reported,
                               const char *handler_uuid, const char *credential_uuid)
{
    uuid_t actual, expected;
    if (!reported || !handler_uuid || !credential_uuid) return false;
    if (uuid_parse(reported->handler_uuid, actual) || uuid_parse(handler_uuid, expected)
        || uuid_is_null(actual) || uuid_compare(actual, expected)) return false;
    if (uuid_parse(reported->credential_uuid, actual) || uuid_parse(credential_uuid, expected)
        || uuid_is_null(actual) || uuid_compare(actual, expected)) return false;
    return true;
}
