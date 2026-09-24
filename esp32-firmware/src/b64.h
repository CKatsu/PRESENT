#pragma once
#include <stddef.h>
#include <stdint.h>
// Base64 standar dengan padding; menulis NUL-terminator. Return panjang string, 0 jika out_cap kurang.
size_t b64_encode(char *out, size_t out_cap, const uint8_t *in, size_t in_len);
