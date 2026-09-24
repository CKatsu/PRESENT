"""
crypto_utils.py
================
Wrapper PRESENT (80-bit & 128-bit key) + mode CBC + PRESENT-CBC-MAC, sesuai
Tabel 1 kerangka "Rancangan Simulasi Benchmarking Algoritma Kriptografi
PRESENT dengan Beban Kerja pada Perangkat IoT".

Spesifikasi algoritma
----------------------
Algoritma  : PRESENT (SPN, 31 round + whitening key akhir), block 64-bit
Varian key : 80-bit dan 128-bit (key length = variabel bebas penelitian)
Sumber     : Bogdanov, A., Knudsen, L.R., Leander, G., Paar, C., Poschmann,
             A., Robshaw, M.J.B., Seurin, Y., Vikkelsoe, C. (2007).
             "PRESENT: An Ultra-Lightweight Block Cipher". CHES 2007,
             LNCS 4727, pp. 450-466. (Varian 128-bit key schedule dijelaskan
             pada bagian 5 paper tsb.; varian ini juga distandarkan pada
             ISO/IEC 29192-2.)

Konvensi byte (PENTING untuk interoperabilitas Python <-> C firmware)
----------------------------------------------------------------------
Semua nilai (block, key) direpresentasikan sebagai byte BIG-ENDIAN, persis
seperti notasi heksadesimal pada paper: byte pertama = byte paling signifikan
(k79..k72 untuk key 80-bit, bit 63..56 untuk block). Tidak ada byte-swap
apa pun di antara Python dan firmware C.

Dua implementasi di file ini (keduanya harus menghasilkan output identik)
--------------------------------------------------------------------------
1. `_ref_*`   : implementasi REFERENSI, mengikuti spesifikasi bit demi bit
                (S-box per nibble, pLayer per bit, key schedule per register).
                Dipakai sebagai "standar" dan untuk cross-check.
2. `PresentKey`: implementasi OPTIMASI (tabel S-box+pLayer gabungan 8x256).
                Ini optimasi IMPLEMENTASI, bukan perubahan algoritma -- hasilnya
                harus identik dengan referensi (diuji pada tests/ dan pada
                _self_test() di bawah). Dipakai untuk benchmark karena PRESENT
                versi referensi di Python sangat lambat untuk payload 1024 byte.
                Catat di laporan bahwa waktu Python-host BUKAN waktu ESP32.

Mode operasi (keputusan desain yang TIDAK ditetapkan eksplisit oleh kerangka --
lihat README bagian "Keputusan desain")
------------------------------------------------------------------------------
- CBC dengan padding PKCS#7 (selalu menambah 1..8 byte). IV 8 byte, dibuat
  baru untuk tiap pesan dan dikirim bersama pesan (IV tidak rahasia).
- MAC = PRESENT-CBC-MAC dengan: (a) kunci MAC TERPISAH dari kunci enkripsi,
  (b) awalan panjang pesan (blok 64-bit berisi panjang data dalam byte) supaya
  aman untuk pesan berbeda panjang (CBC-MAC polos tidak aman untuk pesan
  variabel-panjang), (c) tag = 8 byte penuh (satu blok). Konstruksi:
  encrypt-then-MAC atas (IV || ciphertext).
- Panjang tag hanya 64 bit karena block PRESENT 64 bit -- ini batas bawaan
  desain, dicatat sebagai keterbatasan keamanan (bukan bug).

Validasi (academic integrity)
------------------------------
Modul ini menjalankan `_self_test()` saat di-import: KAT resmi PRESENT-80 dari
paper (Appendix) + round-trip + kesetaraan referensi-vs-tabel. Jika gagal,
import melempar AssertionError -- JANGAN lanjut ke benchmark sebelum lulus.
Lihat tests/test_present_kat.py untuk pengujian formal (termasuk vektor
128-bit, dengan catatan sumbernya).
"""

from __future__ import annotations

import hmac
import struct
from dataclasses import dataclass

BLOCK_BYTES = 8
ROUNDS = 31                  # 31 round + 1 addRoundKey akhir => 32 round key
KEY_BITS_SUPPORTED = (80, 128)
IV_BYTES = 8
TAG_BYTES = 8                # satu blok PRESENT (64 bit)

SBOX = (0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2)
INV_SBOX = tuple(SBOX.index(i) for i in range(16))
MASK64 = (1 << 64) - 1


class AuthError(ValueError):
    """Tag CBC-MAC tidak cocok (pesan dimanipulasi/korup/kunci salah)."""


class PaddingError(ValueError):
    """Padding PKCS#7 tidak valid setelah dekripsi."""


# ---------------------------------------------------------------------------
# 1. IMPLEMENTASI REFERENSI (mengikuti paper apa adanya, lambat)
# ---------------------------------------------------------------------------

def _p(i: int) -> int:
    """Posisi tujuan bit i pada pLayer: P(i) = 16*i mod 63 (i<63), P(63)=63."""
    return 63 if i == 63 else (i * 16) % 63


_PERM = tuple(_p(i) for i in range(64))
_INV_PERM = tuple(_PERM.index(i) for i in range(64))


def _ref_sbox_layer(x: int, box=SBOX) -> int:
    out = 0
    for n in range(16):
        out |= box[(x >> (4 * n)) & 0xF] << (4 * n)
    return out


def _ref_player(x: int) -> int:
    out = 0
    for i in range(64):
        out |= ((x >> i) & 1) << _PERM[i]
    return out


def _ref_inv_player(x: int) -> int:
    out = 0
    for i in range(64):
        out |= ((x >> i) & 1) << _INV_PERM[i]
    return out


def _ref_round_keys(key: bytes) -> list[int]:
    """Key schedule sesuai paper. Return 32 round key (K1..K32), masing-masing 64 bit."""
    key_bits = len(key) * 8
    if key_bits not in KEY_BITS_SUPPORTED:
        raise ValueError(f"Panjang kunci harus 10 atau 16 byte (80/128 bit), dapat {len(key)} byte")
    mask = (1 << key_bits) - 1
    reg = int.from_bytes(key, "big")
    round_keys = []
    for i in range(1, 33):
        round_keys.append(reg >> (key_bits - 64))          # 64 bit paling kiri
        if i == 32:
            break
        reg = ((reg << 61) | (reg >> (key_bits - 61))) & mask   # 1. rotate kiri 61
        if key_bits == 80:                                  # 2. S-box
            top = reg >> 76
            reg = (reg & ~(0xF << 76)) | (SBOX[top] << 76)
            reg ^= i << 15                                  # 3. counter -> k19..k15
        else:
            n1 = reg >> 124
            n2 = (reg >> 120) & 0xF
            reg = (reg & ~(0xFF << 120)) | (SBOX[n1] << 124) | (SBOX[n2] << 120)
            reg ^= i << 62                                  # 3. counter -> k66..k62
    return round_keys


def ref_encrypt_block(key: bytes, block: bytes) -> bytes:
    rk = _ref_round_keys(key)
    x = int.from_bytes(block, "big")
    for i in range(ROUNDS):
        x ^= rk[i]
        x = _ref_player(_ref_sbox_layer(x))
    x ^= rk[ROUNDS]
    return x.to_bytes(8, "big")


def ref_decrypt_block(key: bytes, block: bytes) -> bytes:
    rk = _ref_round_keys(key)
    x = int.from_bytes(block, "big") ^ rk[ROUNDS]
    for i in range(ROUNDS - 1, -1, -1):
        x = _ref_sbox_layer(_ref_inv_player(x), INV_SBOX)
        x ^= rk[i]
    return x.to_bytes(8, "big")


# ---------------------------------------------------------------------------
# 2. IMPLEMENTASI OPTIMASI (tabel gabungan S-box + pLayer) -- hasil identik
# ---------------------------------------------------------------------------

def _build_tables():
    sp = []      # sp[j][b] : kontribusi byte ke-j (bit 8j..8j+7) setelah S-box + pLayer
    ip = []      # ip[j][b] : kontribusi byte ke-j setelah pLayer invers
    for j in range(8):
        row_sp, row_ip = [], []
        for b in range(256):
            # S-box HANYA pada 2 nibble milik byte ini (S-box(0)=0xC, jadi nibble
            # lain tidak boleh ikut disubstitusi), lalu pLayer (linear per bit).
            v_sub = ((SBOX[b >> 4] << 4) | SBOX[b & 0xF]) << (8 * j)
            row_sp.append(_ref_player(v_sub))
            row_ip.append(_ref_inv_player(b << (8 * j)))
        sp.append(tuple(row_sp))
        ip.append(tuple(row_ip))
    isb = tuple((INV_SBOX[b >> 4] << 4) | INV_SBOX[b & 0xF] for b in range(256))
    return tuple(sp), tuple(ip), isb


_SP, _IP, _ISB = _build_tables()
_SP0, _SP1, _SP2, _SP3, _SP4, _SP5, _SP6, _SP7 = _SP
_IP0, _IP1, _IP2, _IP3, _IP4, _IP5, _IP6, _IP7 = _IP


class PresentKey:
    """Konteks kunci: round key dihitung SEKALI (key schedule) lalu dipakai
    berulang -- sama dengan pola firmware (present_key_schedule() sekali)."""

    __slots__ = ("key_bits", "rk")

    def __init__(self, key: bytes):
        self.key_bits = len(key) * 8
        self.rk = tuple(_ref_round_keys(key))

    def encrypt_int(self, x: int) -> int:
        rk = self.rk
        for i in range(ROUNDS):
            x ^= rk[i]
            x = (_SP0[x & 255] | _SP1[(x >> 8) & 255] | _SP2[(x >> 16) & 255] | _SP3[(x >> 24) & 255]
                 | _SP4[(x >> 32) & 255] | _SP5[(x >> 40) & 255] | _SP6[(x >> 48) & 255] | _SP7[x >> 56])
        return x ^ rk[ROUNDS]

    def decrypt_int(self, x: int) -> int:
        rk = self.rk
        x ^= rk[ROUNDS]
        isb = _ISB
        for i in range(ROUNDS - 1, -1, -1):
            x = (_IP0[x & 255] | _IP1[(x >> 8) & 255] | _IP2[(x >> 16) & 255] | _IP3[(x >> 24) & 255]
                 | _IP4[(x >> 32) & 255] | _IP5[(x >> 40) & 255] | _IP6[(x >> 48) & 255] | _IP7[x >> 56])
            x = (isb[x & 255] | (isb[(x >> 8) & 255] << 8) | (isb[(x >> 16) & 255] << 16)
                 | (isb[(x >> 24) & 255] << 24) | (isb[(x >> 32) & 255] << 32)
                 | (isb[(x >> 40) & 255] << 40) | (isb[(x >> 48) & 255] << 48) | (isb[x >> 56] << 56))
            x ^= rk[i]
        return x

    def encrypt_block(self, block: bytes) -> bytes:
        return self.encrypt_int(int.from_bytes(block, "big")).to_bytes(8, "big")

    def decrypt_block(self, block: bytes) -> bytes:
        return self.decrypt_int(int.from_bytes(block, "big")).to_bytes(8, "big")


# ---------------------------------------------------------------------------
# 3. MODE CBC (PKCS#7) dan PRESENT-CBC-MAC
# ---------------------------------------------------------------------------

def pkcs7_pad(data: bytes) -> bytes:
    n = BLOCK_BYTES - (len(data) % BLOCK_BYTES)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_BYTES:
        raise PaddingError("panjang data tidak kelipatan blok")
    n = data[-1]
    if n < 1 or n > BLOCK_BYTES or data[-n:] != bytes([n]) * n:
        raise PaddingError("padding PKCS#7 tidak valid")
    return data[:-n]


def cbc_encrypt(ctx: PresentKey, iv: bytes, plaintext: bytes) -> bytes:
    """C_0=IV, C_i = E_K(P_i xor C_{i-1}). Return ciphertext (tanpa IV)."""
    if len(iv) != IV_BYTES:
        raise ValueError(f"IV harus {IV_BYTES} byte")
    padded = pkcs7_pad(plaintext)
    n = len(padded) // 8
    blocks = struct.unpack(f">{n}Q", padded)
    prev = int.from_bytes(iv, "big")
    enc = ctx.encrypt_int
    out = []
    for p in blocks:
        prev = enc(p ^ prev)
        out.append(prev)
    return struct.pack(f">{n}Q", *out)


def cbc_decrypt(ctx: PresentKey, iv: bytes, ciphertext: bytes) -> bytes:
    if len(iv) != IV_BYTES:
        raise ValueError(f"IV harus {IV_BYTES} byte")
    if not ciphertext or len(ciphertext) % 8:
        raise PaddingError("panjang ciphertext bukan kelipatan blok")
    n = len(ciphertext) // 8
    blocks = struct.unpack(f">{n}Q", ciphertext)
    prev = int.from_bytes(iv, "big")
    dec = ctx.decrypt_int
    out = []
    for c in blocks:
        out.append(dec(c) ^ prev)
        prev = c
    return pkcs7_unpad(struct.pack(f">{n}Q", *out))


def cbc_mac(ctx: PresentKey, data: bytes) -> bytes:
    """PRESENT-CBC-MAC dengan awalan panjang: M' = <len(data) 64-bit BE> || data,
    IV = 0, tag = blok cipher terakhir. `data` harus kelipatan 8 byte."""
    if len(data) % 8:
        raise ValueError("data MAC harus kelipatan 8 byte")
    n = len(data) // 8
    blocks = (len(data),) + (struct.unpack(f">{n}Q", data) if n else ())
    enc = ctx.encrypt_int
    state = 0
    for b in blocks:
        state = enc(b ^ state)
    return state.to_bytes(8, "big")


def mac_input(iv: bytes, ciphertext: bytes) -> bytes:
    """Data yang diautentikasi: IV || ciphertext (IV ikut dilindungi)."""
    return iv + ciphertext


def verify_tag(ctx_mac: PresentKey, iv: bytes, ciphertext: bytes, tag: bytes) -> bool:
    if len(tag) != TAG_BYTES or len(iv) != IV_BYTES or len(ciphertext) % 8:
        return False
    return hmac.compare_digest(cbc_mac(ctx_mac, mac_input(iv, ciphertext)), tag)


# ---------------------------------------------------------------------------
# 4. API tingkat tinggi
# ---------------------------------------------------------------------------

@dataclass
class KeySet:
    """Kunci enkripsi dan kunci MAC (dipisah -- prinsip key separation), dengan
    panjang yang sama (80 atau 128 bit) sesuai varian yang diuji."""
    key_bits: int
    enc: PresentKey
    mac: PresentKey

    @staticmethod
    def from_bytes(enc_key: bytes, mac_key: bytes) -> "KeySet":
        if len(enc_key) != len(mac_key):
            raise ValueError("kunci enkripsi dan MAC harus sama panjang")
        return KeySet(len(enc_key) * 8, PresentKey(enc_key), PresentKey(mac_key))


def seal(ks: KeySet, iv: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt-then-MAC. Return (ciphertext, tag). (device_sim memanggil
    cbc_encrypt & cbc_mac terpisah agar waktunya bisa diukur terpisah.)"""
    ct = cbc_encrypt(ks.enc, iv, plaintext)
    return ct, cbc_mac(ks.mac, mac_input(iv, ct))


def open_(ks: KeySet, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Verifikasi tag DULU (constant-time), baru dekripsi. Raise AuthError /
    PaddingError."""
    if not verify_tag(ks.mac, iv, ciphertext, tag):
        raise AuthError("PRESENT-CBC-MAC tag tidak cocok (pesan ditolak)")
    return cbc_decrypt(ks.enc, iv, ciphertext)


# ---------------------------------------------------------------------------
# 5. Known Answer Test (dijalankan saat import)
# ---------------------------------------------------------------------------

# Vektor uji resmi PRESENT-80: Bogdanov et al. (2007), CHES 2007, Appendix
# ("Test vectors") -- (key, plaintext, ciphertext), semua big-endian hex.
KAT_PRESENT80 = (
    ("00000000000000000000", "0000000000000000", "5579c1387b228445"),
    ("ffffffffffffffffffff", "0000000000000000", "e72c46c0f5945049"),
    ("00000000000000000000", "ffffffffffffffff", "a112ffc72f68417b"),
    ("ffffffffffffffffffff", "ffffffffffffffff", "3333dcd3213210d2"),
)


def _self_test() -> None:
    for key_hex, pt_hex, ct_hex in KAT_PRESENT80:
        key, pt, ct = bytes.fromhex(key_hex), bytes.fromhex(pt_hex), bytes.fromhex(ct_hex)
        assert ref_encrypt_block(key, pt) == ct, f"PRESENT-80 KAT GAGAL (referensi) key={key_hex}"
        assert ref_decrypt_block(key, ct) == pt, f"PRESENT-80 KAT GAGAL (dekripsi referensi) key={key_hex}"
        ctx = PresentKey(key)
        assert ctx.encrypt_block(pt) == ct, f"PRESENT-80 KAT GAGAL (tabel) key={key_hex}"
        assert ctx.decrypt_block(ct) == pt, f"PRESENT-80 KAT GAGAL (dekripsi tabel) key={key_hex}"
    # kesetaraan referensi vs optimasi untuk kedua panjang kunci (input deterministik)
    for klen in (10, 16):
        key = bytes((7 * i + klen) & 0xFF for i in range(klen))
        ctx = PresentKey(key)
        for n in range(8):
            blk = bytes((31 * n + 5 * i + 1) & 0xFF for i in range(8))
            assert ctx.encrypt_block(blk) == ref_encrypt_block(key, blk), "tabel != referensi (enkripsi)"
            assert ctx.decrypt_block(ctx.encrypt_block(blk)) == blk, "round-trip tabel gagal"
    ks = KeySet.from_bytes(bytes(range(16)), bytes(range(16, 32)))
    iv = bytes(range(8))
    for msg in (b"", b"a", b"12345678", b"hello present cbc mac"):
        ct, tag = seal(ks, iv, msg)
        assert open_(ks, iv, ct, tag) == msg, "round-trip CBC+MAC gagal"


_self_test()

if __name__ == "__main__":
    print("PRESENT-80 KAT resmi (Bogdanov et al. 2007): PASSED")
    print(f"Block=64-bit Rounds={ROUNDS}(+1) Tag={TAG_BYTES*8}-bit IV={IV_BYTES*8}-bit")
