#pragma once
// =============================================================================
// present.h -- PRESENT-80/128 (block 64-bit) + CBC (PKCS#7) + PRESENT-CBC-MAC
// Port C dari benchmark-present-iot/crypto_utils.py (implementasi REFERENSI:
// S-box per nibble, pLayer per bit, key schedule per register -- tanpa tabel
// besar, cocok untuk footprint kecil di ESP32).
//
// Konvensi byte: BIG-ENDIAN persis notasi hex paper Bogdanov et al. (2007);
// identik dengan Python (tidak ada byte-swap).
// Tanpa alokasi dinamis. Bisa dikompilasi di PC (gcc) untuk host_test/.
// =============================================================================
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PRESENT_BLOCK_BYTES 8
#define PRESENT_ROUNDS 31
#define PRESENT_IV_BYTES 8
#define PRESENT_TAG_BYTES 8

typedef struct {
    uint64_t rk[32];   // K1..K32
} present_ctx_t;

// key_len: 10 (80-bit) atau 16 (128-bit). Return 0 jika key_len tidak valid.
int present_key_schedule(present_ctx_t *ctx, const uint8_t *key, size_t key_len);

uint64_t present_encrypt_block(const present_ctx_t *ctx, uint64_t block);
uint64_t present_decrypt_block(const present_ctx_t *ctx, uint64_t block);

// CBC + PKCS#7. out_cap harus >= ((in_len / 8) + 1) * 8.
// Return panjang ciphertext (kelipatan 8), atau 0 jika out_cap kurang.
size_t present_cbc_encrypt(const present_ctx_t *ctx, const uint8_t iv[8],
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_cap);

// Return panjang plaintext (setelah unpad) atau -1 jika padding tidak valid.
long present_cbc_decrypt(const present_ctx_t *ctx, const uint8_t iv[8],
                         const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_cap);

// PRESENT-CBC-MAC dengan awalan panjang (blok 64-bit BE berisi len). data_len
// harus kelipatan 8. Menulis 8 byte ke tag.
void present_cbc_mac(const present_ctx_t *ctx, const uint8_t *data, size_t data_len,
                     uint8_t tag[8]);

// Tag = CBC-MAC(IV || ciphertext) -- lihat crypto_utils.mac_input().
void present_tag_iv_ct(const present_ctx_t *mac_ctx, const uint8_t iv[8],
                       const uint8_t *ct, size_t ct_len, uint8_t tag[8]);

// Known Answer Test resmi PRESENT-80 (4 vektor). Return 1 = lulus.
int present_self_test(void);

#ifdef __cplusplus
}
#endif
