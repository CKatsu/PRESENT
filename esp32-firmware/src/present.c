#include "present.h"
#include <string.h>

static const uint8_t SBOX[16] = {0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
                                 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};
static const uint8_t INV_SBOX[16] = {0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD,
                                     0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA};

// ---------------------------------------------------------------- key schedule
// Register disimpan sebagai array byte big-endian (10 atau 16 byte).
// Rotate kiri 61 bit = rotate kiri 7 byte + rotate kiri 5 bit.
static void reg_rotl61(uint8_t *reg, size_t n) {
    uint8_t tmp[16];
    for (size_t i = 0; i < n; i++) tmp[i] = reg[(i + 7) % n];      // 7 byte = 56 bit
    for (size_t i = 0; i < n; i++)                                   // + 5 bit
        reg[i] = (uint8_t)((tmp[i] << 5) | (tmp[(i + 1) % n] >> 3));
}

int present_key_schedule(present_ctx_t *ctx, const uint8_t *key, size_t key_len) {
    if (key_len != 10 && key_len != 16) return 0;
    uint8_t reg[16];
    memcpy(reg, key, key_len);
    for (int i = 1; i <= 32; i++) {
        uint64_t rk = 0;
        for (int b = 0; b < 8; b++) rk = (rk << 8) | reg[b];        // 64 bit paling kiri
        ctx->rk[i - 1] = rk;
        if (i == 32) break;
        reg_rotl61(reg, key_len);
        if (key_len == 10) {
            reg[0] = (uint8_t)((SBOX[reg[0] >> 4] << 4) | (reg[0] & 0x0F));   // k79..k76
            reg[7] ^= (uint8_t)((i >> 1) & 0x0F);                              // k19..k16
            reg[8] ^= (uint8_t)((i & 1) << 7);                                 // k15
        } else {
            reg[0] = (uint8_t)((SBOX[reg[0] >> 4] << 4) | SBOX[reg[0] & 0x0F]); // k127..k120
            reg[7] ^= (uint8_t)((i >> 2) & 0x07);                              // k66..k64
            reg[8] ^= (uint8_t)((i & 3) << 6);                                 // k63..k62
        }
    }
    return 1;
}

// ------------------------------------------------------------------ block op
static uint64_t sbox_layer(uint64_t x, const uint8_t *box) {
    uint64_t out = 0;
    for (int n = 0; n < 16; n++) out |= (uint64_t)box[(x >> (4 * n)) & 0xF] << (4 * n);
    return out;
}

static uint64_t p_layer(uint64_t x) {           // bit i -> posisi 16*i mod 63 (63 tetap)
    uint64_t out = 0;
    for (int i = 0; i < 63; i++) out |= ((x >> i) & 1ULL) << ((i * 16) % 63);
    out |= x & (1ULL << 63);
    return out;
}

static uint64_t inv_p_layer(uint64_t x) {
    uint64_t out = 0;
    for (int i = 0; i < 63; i++) out |= ((x >> ((i * 16) % 63)) & 1ULL) << i;
    out |= x & (1ULL << 63);
    return out;
}

uint64_t present_encrypt_block(const present_ctx_t *ctx, uint64_t x) {
    for (int i = 0; i < PRESENT_ROUNDS; i++) {
        x ^= ctx->rk[i];
        x = p_layer(sbox_layer(x, SBOX));
    }
    return x ^ ctx->rk[PRESENT_ROUNDS];
}

uint64_t present_decrypt_block(const present_ctx_t *ctx, uint64_t x) {
    x ^= ctx->rk[PRESENT_ROUNDS];
    for (int i = PRESENT_ROUNDS - 1; i >= 0; i--) {
        x = sbox_layer(inv_p_layer(x), INV_SBOX);
        x ^= ctx->rk[i];
    }
    return x;
}

static uint64_t load_be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static void store_be64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)v; v >>= 8; }
}

// ----------------------------------------------------------------------- CBC
size_t present_cbc_encrypt(const present_ctx_t *ctx, const uint8_t iv[8],
                           const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap) {
    size_t pad = 8 - (in_len % 8);
    size_t total = in_len + pad;
    if (out_cap < total) return 0;
    uint64_t prev = load_be64(iv);
    for (size_t off = 0; off < total; off += 8) {
        uint8_t blk[8];
        for (int i = 0; i < 8; i++) {
            size_t idx = off + (size_t)i;
            blk[i] = (idx < in_len) ? in[idx] : (uint8_t)pad;       // PKCS#7
        }
        prev = present_encrypt_block(ctx, load_be64(blk) ^ prev);
        store_be64(out + off, prev);
    }
    return total;
}

long present_cbc_decrypt(const present_ctx_t *ctx, const uint8_t iv[8],
                         const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap) {
    if (in_len == 0 || (in_len % 8) != 0 || out_cap < in_len) return -1;
    uint64_t prev = load_be64(iv);
    for (size_t off = 0; off < in_len; off += 8) {
        uint64_t c = load_be64(in + off);
        store_be64(out + off, present_decrypt_block(ctx, c) ^ prev);
        prev = c;
    }
    uint8_t n = out[in_len - 1];
    if (n < 1 || n > 8) return -1;
    for (uint8_t i = 0; i < n; i++)
        if (out[in_len - 1 - i] != n) return -1;
    return (long)(in_len - n);
}

// ------------------------------------------------------------------- CBC-MAC
void present_cbc_mac(const present_ctx_t *ctx, const uint8_t *data, size_t data_len,
                     uint8_t tag[8]) {
    uint64_t state = present_encrypt_block(ctx, (uint64_t)data_len);   // blok awalan panjang
    for (size_t off = 0; off + 8 <= data_len; off += 8)
        state = present_encrypt_block(ctx, load_be64(data + off) ^ state);
    store_be64(tag, state);
}

void present_tag_iv_ct(const present_ctx_t *mac_ctx, const uint8_t iv[8],
                       const uint8_t *ct, size_t ct_len, uint8_t tag[8]) {
    // MAC atas (IV || ct) tanpa menyalin: panjang total = 8 + ct_len
    uint64_t state = present_encrypt_block(mac_ctx, (uint64_t)(8 + ct_len));
    state = present_encrypt_block(mac_ctx, load_be64(iv) ^ state);
    for (size_t off = 0; off + 8 <= ct_len; off += 8)
        state = present_encrypt_block(mac_ctx, load_be64(ct + off) ^ state);
    store_be64(tag, state);
}

// ------------------------------------------------------------------------ KAT
int present_self_test(void) {
    static const uint8_t KEYS[4][10] = {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
    static const uint64_t PT[4] = {0x0000000000000000ULL, 0x0000000000000000ULL,
                                   0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};
    static const uint64_t CT[4] = {0x5579C1387B228445ULL, 0xE72C46C0F5945049ULL,
                                   0xA112FFC72F68417BULL, 0x3333DCD3213210D2ULL};
    for (int i = 0; i < 4; i++) {
        present_ctx_t ctx;
        if (!present_key_schedule(&ctx, KEYS[i], 10)) return 0;
        if (present_encrypt_block(&ctx, PT[i]) != CT[i]) return 0;
        if (present_decrypt_block(&ctx, CT[i]) != PT[i]) return 0;
    }
    return 1;
}
