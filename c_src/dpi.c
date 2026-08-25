#include <stdio.h>
#include <string.h>

static const char *SIGNATURES[] = {
    "' OR '1'='1",
    "UNION SELECT",
    "<script>",
    "../",
    "etc/passwd",
    "cmd.exe",
    NULL
};

#if defined(_WIN32) || defined(_WIN64)
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT
#endif

EXPORT int inspect_payload(const char* payload, int payload_len) {
    if (!payload || payload_len <= 0) return 0;
    for (int i = 0; SIGNATURES[i] != NULL; i++) {
        if (strstr(payload, SIGNATURES[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

EXPORT int inspect_batch(const char** payloads, const int* lengths, int count, int* results) {
    if (!payloads || !lengths || !results) return 0;
    for (int i = 0; i < count; i++) {
        results[i] = inspect_payload(payloads[i], lengths[i]);
    }
    return 1;
}