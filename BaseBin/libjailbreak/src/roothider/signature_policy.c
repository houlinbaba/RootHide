#include "signature_policy.h"
#include <string.h>

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16)
        | ((uint32_t)bytes[2] << 8) | bytes[3];
}

bool roothide_signature_normalized_flags(const void *directory, size_t size,
                                        bool usesSPTM, uint32_t *flagsOut)
{
    if (!directory || !flagsOut || size < 44
        || size > ROOTHIDE_SIGNATURE_MAX_DIRECTORY_SIZE) return false;
    const uint8_t *bytes = directory;
    uint32_t version = read_be32(bytes + 8);
    if (read_be32(bytes) != 0xfade0c02 || read_be32(bytes + 4) != size
        || version < 0x20000) return false;

    size_t headerSize = version >= 0x20600 ? 112 : version >= 0x20500 ? 96
        : version >= 0x20400 ? 88 : version >= 0x20300 ? 64
        : version >= 0x20200 ? 52 : version >= 0x20100 ? 48 : 44;
    if (size < headerSize) return false;

    uint32_t hashOffset = read_be32(bytes + 16);
    if (hashOffset < headerSize || hashOffset > size
        || (uint64_t)read_be32(bytes + 24) * bytes[36] > hashOffset - headerSize) return false;

    bool hasTeamID = false;
    if (version >= 0x20200) {
        uint32_t teamOffset = read_be32(bytes + 48);
        if (teamOffset) {
            if (teamOffset < headerSize || teamOffset >= size) return false;
            const uint8_t *team = bytes + teamOffset;
            if (!memchr(team, 0, size - teamOffset)) return false;
            hasTeamID = team[0] != 0;
        }
    }

    uint32_t flags = read_be32(bytes + 12);
    // TXM requires exactly one of CS_ADHOC and a nonempty Team ID. This
    // runtime path handles CMS-free wrappers, including wrappers with flags=0.
    // Preserve the existing iOS 16 behavior on devices without SPTM/TXM.
    if (usesSPTM) {
        flags = hasTeamID ? flags & ~ROOTHIDE_SIGNATURE_FLAG_ADHOC
                          : flags | ROOTHIDE_SIGNATURE_FLAG_ADHOC;
    }
    *flagsOut = flags;
    return true;
}
