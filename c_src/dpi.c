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

/*
 * NOTE on signature lengths: DPI over raw/encrypted traffic risks false
 * positives when a signature is short enough to appear by chance in
 * high-entropy (e.g. TLS-encrypted) byte streams. "../" at 3 bytes was too
 * short for this; "../../" at 6 bytes is a much safer minimum. As a rule of
 * thumb, avoid substring signatures under ~5-6 bytes for byte-level scanning.
 */
static const Signature SIGNATURES[] = {
    {"' OR '1'='1", 11},
    {"UNION SELECT", 12},
    {"<script>",     8},
    {"../../",       6},
    {"etc/passwd",  10},
    {"cmd.exe",      7},
    {"; whoami",     8},
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

/*
 * Returns the index into SIGNATURES of the first matching pattern, or -1
 * if none matched. Lets callers (e.g. main.py) log exactly which signature
 * fired instead of a generic "match" — useful for debugging false positives.
 */
EXPORT int inspect_payload_index(const char* payload, int payload_len) {
    if (!payload || payload_len <= 0) return -1;

    for (int i = 0; SIGNATURES[i].pattern != NULL; i++) {
        if (safe_payload_contains(payload, (size_t)payload_len, SIGNATURES[i].pattern, SIGNATURES[i].len)) {
            return i;
        }
    }
    return -1;
}

EXPORT int inspect_payload(const char* payload, int payload_len) {
    return inspect_payload_index(payload, payload_len) >= 0 ? 1 : 0;
}

EXPORT int inspect_batch(const char** payloads, const int* lengths, int count, int* results) {
    if (!payloads || !lengths || !results || count <= 0) return 0;

    for (int i = 0; i < count; i++) {
        results[i] = inspect_payload(payloads[i], lengths[i]);
    }
    return 1;
}