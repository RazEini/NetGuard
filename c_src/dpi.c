#include <stdio.h>
#include <string.h>

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

#if defined(_WIN32) || defined(_WIN64)
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

static int mem_contains(const char *haystack, size_t haystack_len, const char *needle, size_t needle_len) {
    if (needle_len > haystack_len) return 0;
    size_t max_idx = haystack_len - needle_len;
    for (size_t i = 0; i <= max_idx; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0) {
            return 1;
        }
    }
    return 0;
}

EXPORT int inspect_payload(const char* payload, int payload_len) {
    if (!payload || payload_len <= 0) return 0;

    for (int i = 0; SIGNATURES[i].pattern != NULL; i++) {
        if (mem_contains(payload, (size_t)payload_len, SIGNATURES[i].pattern, SIGNATURES[i].len)) {
            return 1; // Match found
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
