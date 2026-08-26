#include <stdio.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

typedef struct {
    const char *pattern;
    size_t len;
} Signature;

static const Signature SIGNATURES[] = {
    {"' OR '1'='1", 11},
    {"UNION SELECT", 12},
    {"<script>",     8},
    {"../",          3},
    {"etc/passwd",  10},
    {"cmd.exe",      7},
    {NULL,          0}
};

/* 
 * Safe substring matching for raw binary payloads.
 * Avoids strstr() to prevent out-of-bounds reads on non-null-terminated buffers.
 */
static inline int safe_payload_contains(const char *payload, size_t payload_len, const char *pattern, size_t pattern_len) {
    if (pattern_len > payload_len || pattern_len == 0) return 0;

    const char *ptr = payload;
    size_t remaining = payload_len;

    while (remaining >= pattern_len) {
        // Fast-forward to candidate byte using SIMD-optimized libc memchr
        ptr = (const char *)memchr(ptr, pattern[0], remaining - pattern_len + 1);
        if (!ptr) return 0;

        // Exact bound-checked byte comparison
        if (memcmp(ptr, pattern, pattern_len) == 0) {
            return 1;
        }

        ptr++;
        remaining = payload_len - (size_t)(ptr - payload);
    }
    return 0;
}

EXPORT int inspect_payload(const char* payload, int payload_len) {
    if (!payload || payload_len <= 0) return 0;

    for (int i = 0; SIGNATURES[i].pattern != NULL; i++) {
        if (safe_payload_contains(payload, (size_t)payload_len, SIGNATURES[i].pattern, SIGNATURES[i].len)) {
            return 1;
        }
    }
    return 0;
}

EXPORT int inspect_batch(const char** payloads, const int* lengths, int count, int* results) {
    if (!payloads || !lengths || !results || count <= 0) return 0;

    for (int i = 0; i < count; i++) {
        results[i] = inspect_payload(payloads[i], lengths[i]);
    }
    return 1;
}
