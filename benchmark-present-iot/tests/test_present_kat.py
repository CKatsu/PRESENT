"""
tests/test_present_kat.py
==========================
Known Answer Test formal untuk crypto_utils.py. Jalankan:
    python3 tests/test_present_kat.py        (atau: python3 -m pytest tests/)

WAJIB LULUS sebelum pengambilan data benchmark apa pun.

Status sumber vektor uji (jujur, agar bisa dipertanggungjawabkan di skripsi):
  * PRESENT-80  : 4 vektor RESMI dari Bogdanov et al. (2007), CHES 2007,
                  Appendix. Nilai yang sama tercantum di dokumentasi SageMath
                  (modul crypto.block_cipher.present) -- dicocokkan saat
                  pengembangan.
  * PRESENT-128 : paper asli TIDAK memuat vektor uji 128-bit. Vektor di bawah
                  berasal dari sumber SEKUNDER (nilai yang beredar pada
                  implementasi referensi komunitas) dan saat pengembangan
                  hanya dikorroborasi oleh implementasi independen milik
                  proyek ini (referensi bit-demi-bit == tabel == C firmware).
                  BELUM diverifikasi terhadap dokumen primer/standar
                  (mis. ISO/IEC 29192-2). >>> Verifikasi sendiri sebelum
                  mengutipnya sebagai "KAT resmi" di laporan. <<<
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto_utils as cu  # noqa: E402

KAT_128_SECONDARY = (
    ("00" * 16, "00" * 8, "96db702a2e6900af"),
    ("ff" * 16, "00" * 8, "13238c710272a5d8"),
    ("ff" * 16, "ff" * 8, "628d9fbd4218e5b4"),
    ("00" * 16, "ff" * 8, "3c6019e5e5edd563"),   # hanya dari implementasi ini (belum ada sumber luar)
)


def test_present80_official_kat():
    for k, p, c in cu.KAT_PRESENT80:
        key, pt, ct = bytes.fromhex(k), bytes.fromhex(p), bytes.fromhex(c)
        assert cu.ref_encrypt_block(key, pt) == ct
        assert cu.PresentKey(key).encrypt_block(pt) == ct
        assert cu.PresentKey(key).decrypt_block(ct) == pt


def test_present128_secondary_vectors():
    for k, p, c in KAT_128_SECONDARY:
        key, pt, ct = bytes.fromhex(k), bytes.fromhex(p), bytes.fromhex(c)
        assert cu.ref_encrypt_block(key, pt) == ct
        assert cu.PresentKey(key).encrypt_block(pt) == ct
        assert cu.PresentKey(key).decrypt_block(ct) == pt


def test_optimized_equals_reference_random():
    import random
    rng = random.Random(1)
    for klen in (10, 16):
        for _ in range(60):
            key = rng.randbytes(klen)
            blk = rng.randbytes(8)
            ctx = cu.PresentKey(key)
            assert ctx.encrypt_block(blk) == cu.ref_encrypt_block(key, blk)
            assert ctx.decrypt_block(blk) == cu.ref_decrypt_block(key, blk)


def test_invalid_key_length():
    for n in (0, 9, 11, 15, 17, 32):
        try:
            cu.PresentKey(bytes(n))
            assert False, f"kunci {n} byte seharusnya ditolak"
        except ValueError:
            pass


def test_cbc_roundtrip_all_lengths_both_keys():
    import random
    rng = random.Random(2)
    for klen in (10, 16):
        ks = cu.KeySet.from_bytes(rng.randbytes(klen), rng.randbytes(klen))
        for n in list(range(0, 40)) + [63, 64, 65, 255, 256, 1023, 1024]:
            pt, iv = rng.randbytes(n), rng.randbytes(8)
            ct, tag = cu.seal(ks, iv, pt)
            assert len(ct) == (n // 8 + 1) * 8            # PKCS#7: selalu +1..8 byte
            assert cu.open_(ks, iv, ct, tag) == pt


def test_cbc_hides_repeated_blocks():
    """Payload 1024B hasil padding spasi (blok plaintext identik berulang) tidak
    boleh menghasilkan blok ciphertext identik (bukti mode CBC, bukan ECB)."""
    ks = cu.KeySet.from_bytes(bytes(range(10)), bytes(range(10, 20)))
    pt = b"{" + b" " * 1022 + b"}"
    ct, _ = cu.seal(ks, bytes(8), pt)
    blocks = [ct[i:i + 8] for i in range(0, len(ct), 8)]
    assert len(set(blocks)) == len(blocks)


def test_tamper_every_bit_of_ct_iv_tag_detected():
    ks = cu.KeySet.from_bytes(bytes(range(16)), bytes(range(16, 32)))
    iv = bytes(range(8))
    ct, tag = cu.seal(ks, iv, b'{"t":28.5}' + b" " * 30)
    for i in range(len(ct) * 8):
        bad = bytearray(ct); bad[i // 8] ^= 1 << (i % 8)
        assert not cu.verify_tag(ks.mac, iv, bytes(bad), tag)
    for i in range(64):
        bad = bytearray(iv); bad[i // 8] ^= 1 << (i % 8)
        assert not cu.verify_tag(ks.mac, bytes(bad), ct, tag)
        badt = bytearray(tag); badt[i // 8] ^= 1 << (i % 8)
        assert not cu.verify_tag(ks.mac, iv, ct, bytes(badt))
    wrong = cu.KeySet.from_bytes(bytes(16), bytes(range(16, 32)))
    try:
        cu.open_(wrong, iv, ct, tag)   # kunci enkripsi salah tapi MAC benar -> lolos MAC, gagal/berbeda saat dekripsi
    except cu.PaddingError:
        pass
    wrong_mac = cu.KeySet.from_bytes(bytes(range(16)), bytes(16))
    try:
        cu.open_(wrong_mac, iv, ct, tag)
        assert False
    except cu.AuthError:
        pass


def test_mac_length_prefix_blocks_extension():
    """Tanpa awalan panjang, tag(m1) dapat dipakai menyambung ke m1||m2 (bug klasik
    CBC-MAC variabel-panjang). Dengan awalan panjang, tag pesan yang diperpanjang
    berbeda dari tag pesan asli."""
    ks = cu.KeySet.from_bytes(bytes(range(10)), bytes(range(10, 20)))
    m = bytes(range(16))
    assert cu.cbc_mac(ks.mac, m) != cu.cbc_mac(ks.mac, m + bytes(8))
    assert cu.cbc_mac(ks.mac, m) != cu.cbc_mac(ks.mac, m[:8])


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"  ok  {name}")
    print("ALL KAT / CBC / CBC-MAC / tamper tests PASSED")
