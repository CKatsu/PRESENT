// Harness host (PC) untuk present.c -- dipakai tests/crosscheck_c.py.
// Kompilasi: gcc -O2 -I../src present_host_test.c ../src/present.c -o present_host_test
// Mode:
//   ./present_host_test selftest         -> KAT resmi PRESENT-80 di sisi C
//   ./present_host_test < vektor.txt     -> tiap baris: enc_key_hex mac_key_hex iv_hex pt_hex
//                                           keluaran : ct_hex tag_hex  (atau "ERR")
//                                           + memverifikasi round-trip dekripsi C sendiri
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "present.h"

static int hex2bytes(const char *h, uint8_t *out, size_t cap) {
    size_t n = strlen(h);
    if (n % 2 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return (int)(n / 2);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "selftest") == 0) {
        int ok = present_self_test();
        printf("C PRESENT-80 KAT: %s\n", ok ? "PASSED" : "FAILED");
        return ok ? 0 : 1;
    }
    static char ek[64], mk[64], ivh[32], pth[8192];
    while (scanf("%63s %63s %31s %8191s", ek, mk, ivh, pth) == 4) {
        uint8_t enc_key[16], mac_key[16], iv[8];
        static uint8_t pt[4096], ct[4104], back[4104];
        int ekl = hex2bytes(ek, enc_key, 16), mkl = hex2bytes(mk, mac_key, 16);
        int ivl = hex2bytes(ivh, iv, 8);
        int ptl = (strcmp(pth, "-") == 0) ? 0 : hex2bytes(pth, pt, sizeof pt);
        present_ctx_t ec, mc;
        if (ekl < 0 || mkl < 0 || ivl != 8 || ptl < 0 ||
            !present_key_schedule(&ec, enc_key, (size_t)ekl) ||
            !present_key_schedule(&mc, mac_key, (size_t)mkl)) { puts("ERR"); continue; }
        size_t cl = present_cbc_encrypt(&ec, iv, pt, (size_t)ptl, ct, sizeof ct);
        uint8_t tag[8], tag2[8];
        present_tag_iv_ct(&mc, iv, ct, cl, tag);
        // konsistensi internal: MAC(iv||ct) lewat present_cbc_mac harus sama
        static uint8_t buf[4200];
        memcpy(buf, iv, 8); memcpy(buf + 8, ct, cl);
        present_cbc_mac(&mc, buf, 8 + cl, tag2);
        long bl = present_cbc_decrypt(&ec, iv, ct, cl, back, sizeof back);
        if (memcmp(tag, tag2, 8) != 0 || bl != ptl || (ptl && memcmp(back, pt, (size_t)ptl) != 0)) {
            puts("ERR"); continue;
        }
        for (size_t i = 0; i < cl; i++) printf("%02x", ct[i]);
        putchar(' ');
        for (int i = 0; i < 8; i++) printf("%02x", tag[i]);
        putchar('\n');
    }
    return 0;
}
