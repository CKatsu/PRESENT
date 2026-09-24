"""
tests/crosscheck_c.py
======================
Cross-check implementasi C firmware (esp32-firmware/src/present.c) terhadap
implementasi Python (crypto_utils.py) pada vektor deterministik + acak
(seed tetap): kunci 80 & 128 bit, panjang plaintext 0..1024 byte.

Ini memenuhi syarat "KAT lulus di KEDUA sisi": (1) sisi C menjalankan KAT resmi
PRESENT-80 sendiri (`present_host_test selftest`), (2) output C == output Python
untuk ciphertext (CBC) dan tag (CBC-MAC) pada semua vektor.

Butuh compiler C (gcc/clang). Jalankan:  python3 tests/crosscheck_c.py
"""
import os
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import crypto_utils as cu  # noqa: E402

FW = os.path.join(os.path.dirname(ROOT), "esp32-firmware")


def build(outdir: str) -> str:
    cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
    if not cc:
        raise SystemExit("compiler C tidak ditemukan (gcc/clang)")
    exe = os.path.join(outdir, "present_host_test")
    subprocess.check_call([cc, "-O2", "-Wall", "-Wextra", "-I", os.path.join(FW, "src"),
                           os.path.join(FW, "host_test", "present_host_test.c"),
                           os.path.join(FW, "src", "present.c"), "-o", exe])
    return exe


def main() -> int:
    rng = random.Random(20260924)
    with tempfile.TemporaryDirectory() as tmp:
        exe = build(tmp)
        r = subprocess.run([exe, "selftest"], capture_output=True, text=True)
        print(r.stdout.strip())
        if r.returncode != 0:
            print("C KAT GAGAL -- hentikan, jangan benchmark.")
            return 1

        lines, expected = [], []
        # 1) blok tunggal: iv=0, pt 8 byte => ct[:8] = E_K(pt)  (KAT-style, kedua panjang kunci)
        for klen in (10, 16):
            for kfill, pfill in ((0x00, 0x00), (0xFF, 0x00), (0x00, 0xFF), (0xFF, 0xFF)):
                ek = bytes([kfill]) * klen
                mk = bytes([0x11]) * klen
                pt = bytes([pfill]) * 8
                lines.append(f"{ek.hex()} {mk.hex()} {'00'*8} {pt.hex()}")
                ks = cu.KeySet.from_bytes(ek, mk)
                ct, tag = cu.seal(ks, bytes(8), pt)
                expected.append(f"{ct.hex()} {tag.hex()}")
        # 2) acak, panjang 0..1024, kedua panjang kunci
        for _ in range(300):
            klen = rng.choice((10, 16))
            ek, mk = rng.randbytes(klen), rng.randbytes(klen)
            iv = rng.randbytes(8)
            n = rng.choice((0, 1, 7, 8, 9, 63, 64, 65, 255, 256, 1023, 1024, rng.randrange(0, 1025)))
            pt = rng.randbytes(n)
            lines.append(f"{ek.hex()} {mk.hex()} {iv.hex()} {pt.hex() if n else '-'}")
            ct, tag = cu.seal(cu.KeySet.from_bytes(ek, mk), iv, pt)
            expected.append(f"{ct.hex()} {tag.hex()}")

        r = subprocess.run([exe], input="\n".join(lines) + "\n", capture_output=True, text=True)
        got = r.stdout.strip().split("\n")
        if len(got) != len(expected):
            print(f"jumlah baris keluaran C ({len(got)}) != {len(expected)}")
            return 1
        bad = [i for i, (g, e) in enumerate(zip(got, expected)) if g != e]
        if bad:
            i = bad[0]
            print(f"MISMATCH {len(bad)}/{len(expected)}; contoh #{i}:\n in : {lines[i][:120]}\n C  : {got[i][:120]}\n Py : {expected[i][:120]}")
            return 1
        print(f"Cross-check C vs Python: {len(expected)} vektor identik (CBC ciphertext + CBC-MAC tag) -> PASSED")
        return 0


if __name__ == "__main__":
    sys.exit(main())
