"""
attacker.py
===========
Simulasi paket tampered untuk skenario S4 (Tabel 1 & bagian 6 kerangka).
Empat varian (persis seperti kerangka):

  flip_ciphertext_bit : membalik SATU bit acak pada ciphertext
  random_tag          : mengganti tag autentikasi dengan nilai acak
  modify_iv           : mengubah IV (tidak sama dengan IV saat enkripsi)
  wrong_key           : pengirim memakai kunci rahasia yang BERBEDA (kunci ENC dan MAC
                        keduanya, tiap byte di-XOR config.WRONG_KEY_XOR)

Model ancaman: penyerang di jalur komunikasi TANPA mengetahui kunci (tiga varian
pertama beroperasi pada paket di level-kabel, bukan pada plaintext). `wrong_key`
memodelkan perangkat palsu/salah-konfigurasi. Ini BUKAN kriptanalisis PRESENT dan
tidak mencakup serangan lapisan jaringan (lihat batasan kerangka bagian 8).
"""

from __future__ import annotations

import base64
import copy
import random
from typing import Optional

import config
import crypto_utils as cu

VARIANTS = config.S4_TAMPER_VARIANTS


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _mark(env: dict, variant: str) -> dict:
    env["condition"] = "tampered"
    env["tv"] = variant
    return env


def flip_ciphertext_bit(env: dict, rng: random.Random) -> dict:
    out = copy.deepcopy(env)
    raw = bytearray(_b64d(out["ct"]))
    i = rng.randrange(len(raw) * 8)
    raw[i // 8] ^= 1 << (i % 8)
    out["ct"] = _b64e(bytes(raw))
    return _mark(out, "flip_ciphertext_bit")


def random_tag(env: dict, rng: random.Random) -> dict:
    out = copy.deepcopy(env)
    orig = _b64d(out["tag"])
    new = orig
    while new == orig:                       # pastikan benar-benar berbeda
        new = rng.randbytes(cu.TAG_BYTES)
    out["tag"] = _b64e(new)
    return _mark(out, "random_tag")


def modify_iv(env: dict, rng: random.Random) -> dict:
    out = copy.deepcopy(env)
    orig = bytes.fromhex(out["iv"])
    new = orig
    while new == orig:
        new = rng.randbytes(cu.IV_BYTES)
    out["iv"] = new.hex()
    return _mark(out, "modify_iv")


def wrong_keyset(key_bits: int) -> cu.KeySet:
    k = config.KEYS[key_bits]
    x = config.WRONG_KEY_XOR
    return cu.KeySet.from_bytes(bytes(b ^ x for b in k["enc"]), bytes(b ^ x for b in k["mac"]))


def wrong_key(env: dict, *, plaintext: bytes, iv: bytes, key_bits: int) -> dict:
    """Bangun ulang paket dengan kunci yang salah (envelope lain dipertahankan)."""
    out = copy.deepcopy(env)
    ct, tag = cu.seal(wrong_keyset(key_bits), iv, plaintext)
    out["ct"], out["tag"] = _b64e(ct), _b64e(tag)
    return _mark(out, "wrong_key")


def make_tampered(variant: str, env: dict, rng: random.Random, *,
                  plaintext: Optional[bytes] = None, iv: Optional[bytes] = None,
                  key_bits: Optional[int] = None) -> dict:
    if variant == "flip_ciphertext_bit":
        return flip_ciphertext_bit(env, rng)
    if variant == "random_tag":
        return random_tag(env, rng)
    if variant == "modify_iv":
        return modify_iv(env, rng)
    if variant == "wrong_key":
        if plaintext is None or iv is None or key_bits is None:
            raise ValueError("wrong_key butuh plaintext, iv, key_bits")
        return wrong_key(env, plaintext=plaintext, iv=iv, key_bits=key_bits)
    raise ValueError(f"varian tampered tidak dikenal: {variant}")
