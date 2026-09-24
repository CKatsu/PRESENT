#include "b64.h"

size_t b64_encode(char *out, size_t out_cap, const uint8_t *in, size_t in_len) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t need = ((in_len + 2) / 3) * 4 + 1;
    if (out_cap < need) return 0;
    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < in_len) v |= in[i + 2];
        out[o++] = T[(v >> 18) & 63];
        out[o++] = T[(v >> 12) & 63];
        out[o++] = (i + 1 < in_len) ? T[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < in_len) ? T[v & 63] : '=';
    }
    out[o] = '\0';
    return o;
}
