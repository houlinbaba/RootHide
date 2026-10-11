#ifndef ROOTHIDE_SIGNATURE_POLICY_H
#define ROOTHIDE_SIGNATURE_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ROOTHIDE_SIGNATURE_FLAG_ADHOC 0x2u
#define ROOTHIDE_SIGNATURE_MAX_DIRECTORY_SIZE (16u * 1024u * 1024u)

// Reads an on-disk (big-endian) CodeDirectory. Invalid Team ID metadata is
// rejected rather than treated as an absent Team ID. Other flag bits survive.
bool roothide_signature_normalized_flags(const void *directory, size_t size,
                                        bool usesSPTM, uint32_t *flagsOut);

#endif
