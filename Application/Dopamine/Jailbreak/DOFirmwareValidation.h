#ifndef DO_FIRMWARE_VALIDATION_H
#define DO_FIRMWARE_VALIDATION_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Apple's firmware CDN uses cdn-apple.com in addition to apple.com.
// Match the whole domain or a subdomain boundary, never a bare suffix.
static inline bool do_firmware_apple_host(const char *host)
{
    if (!host) return false;
    size_t length = strlen(host);
    const char *domains[] = {"apple.com", "cdn-apple.com"};
    for (size_t i = 0; i < sizeof(domains) / sizeof(domains[0]); i++) {
        size_t domainLength = strlen(domains[i]);
        if (length >= domainLength &&
            memcmp(host + length - domainLength, domains[i], domainLength) == 0 &&
            (length == domainLength || host[length - domainLength - 1] == '.')) return true;
    }
    return false;
}

// Only accept a complete IM4P container. XPF handles payload decompression;
// the BuildManifest digest binds the whole container to the selected identity.
static inline bool do_firmware_der(const uint8_t **cursor, const uint8_t *end,
                                   uint8_t tag, const uint8_t **value, size_t *length)
{
    if ((size_t)(end - *cursor) < 2 || *(*cursor)++ != tag) return false;
    size_t size = *(*cursor)++;
    if (size & 0x80) {
        size_t count = size & 0x7f;
        if (!count || count > sizeof(size_t) || (size_t)(end - *cursor) < count) return false;
        size = 0;
        while (count--) {
            if (size > (SIZE_MAX >> 8)) return false;
            size = (size << 8) | *(*cursor)++;
        }
    }
    if (size > (size_t)(end - *cursor)) return false;
    *value = *cursor;
    *length = size;
    *cursor += size;
    return true;
}

static inline bool do_firmware_im4p(const void *bytes, size_t size, const char *type)
{
    if (!bytes || size < 2 || size > 64 * 1024 * 1024) return false;
    const uint8_t *cursor = bytes, *end = cursor + size, *sequence, *value;
    size_t length;
    if (!do_firmware_der(&cursor, end, 0x30, &sequence, &length) || cursor != end) return false;
    cursor = sequence;
    end = sequence + length;
    if (!do_firmware_der(&cursor, end, 0x16, &value, &length) || length != 4 || memcmp(value, "IM4P", 4)) return false;
    if (!do_firmware_der(&cursor, end, 0x16, &value, &length) || length != 4 || memcmp(value, type, 4)) return false;
    if (!do_firmware_der(&cursor, end, 0x16, &value, &length)) return false;
    if (!do_firmware_der(&cursor, end, 0x04, &value, &length) || !length) return false;
    // Additional compression metadata may follow the payload inside IM4P.
    return true;
}
#endif
