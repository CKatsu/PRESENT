"""
tests/test_firmware_host.py
============================
Menjalankan src/main.cpp firmware ASLI di PC (stub Arduino, bukan hardware) lalu
memasukkan paket yang dihasilkannya ke Receiver Python. Membuktikan bahwa logika
aplikasi firmware (payload JSON, IV, PKCS#7, CBC, CBC-MAC, base64, envelope) kompatibel
dengan receiver, untuk key 80 & 128 bit, payload 64/256/1024 B, dan demo tampered.
Juga syntax-check varian MQTT (stub WiFi/PubSubClient).

TIDAK membuktikan: perilaku pada hardware ESP32-S3 (timing, I2C BME280, USB-serial,
WiFi/MQTT sungguhan) dan kompilasi dengan toolchain PlatformIO -- itu harus Anda uji
(`pio run` lalu upload).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FW = os.path.join(os.path.dirname(ROOT), "esp32-firmware")
sys.path.insert(0, ROOT)
import receiver_server as rs  # noqa: E402


def build(out, defs):
    gcc, gxx = shutil.which("gcc"), shutil.which("g++")
    if not (gcc and gxx):
        raise SystemExit("butuh gcc & g++")
    inc = ["-I", os.path.join(FW, "src"), "-I", os.path.join(FW, "include"), "-I", os.path.join(FW, "host_test", "stubs")]
    obj = os.path.join(out, "present.o")
    subprocess.check_call([gcc, "-O2", "-Wall", "-Wextra", "-c", os.path.join(FW, "src", "present.c"), "-o", obj] + inc)
    exe = os.path.join(out, "fw_host")
    srcs = [os.path.join(FW, "src", f) for f in ("main.cpp", "payload.cpp", "sensor.cpp", "b64.cpp")]
    subprocess.check_call([gxx, "-O2", "-Wall", "-Wextra", "-std=gnu++17", "-Wno-unused-parameter"] + defs + inc +
                          srcs + [os.path.join(FW, "host_test", "firmware_host_main.cpp"), obj, "-o", exe])
    return exe


def run_case(out, key_bits, payload, tamper_every=0):
    defs = [f"-DPRESENT_KEY_BITS={key_bits}", f"-DPAYLOAD_TARGET_SIZE_BYTES={payload}"]
    if tamper_every:
        defs.append(f"-DTAMPER_DEMO_EVERY_N_MESSAGES={tamper_every}")
    exe = build(out, defs)
    txt = subprocess.run([exe, "10"], capture_output=True, text=True, check=True).stdout
    assert "KAT resmi PRESENT-80 (Bogdanov et al. 2007): PASSED" in txt, "KAT firmware tidak lulus"
    assert "SINTETIS (BME280 belum" in txt
    recv = rs.Receiver(writer=None, monitor=None)
    n_ok = n_rej = 0
    seqs = []
    for line in txt.splitlines():
        if not line.startswith("PRS1:"):
            continue
        msg = json.loads(line[5:])
        ack = recv.handle(msg, "uart", "serial")
        seqs.append(msg["seq"])
        assert msg["key_bits"] == key_bits and "enc_us" in msg
        if msg["condition"] == "normal":
            assert ack["accepted"], f"firmware->receiver DITOLAK: {ack} (key={key_bits}, payload={payload})"
            n_ok += 1
        else:
            assert not ack["accepted"] and ack["reason"] == "tag_mismatch", ack
            n_rej += 1
    assert seqs == list(range(len(seqs))) and len(seqs) >= 5, seqs
    return n_ok, n_rej


def syntax_check_mqtt(out):
    gxx = shutil.which("g++")
    inc = ["-I", os.path.join(FW, "src"), "-I", os.path.join(FW, "include"), "-I", os.path.join(FW, "host_test", "stubs")]
    subprocess.check_call([gxx, "-fsyntax-only", "-std=gnu++17", "-Wall", "-Wextra", "-Wno-unused-parameter",
                           "-DPRESENT_TRANSPORT_MQTT"] + inc + [os.path.join(FW, "src", "main.cpp")])


def main():
    out = tempfile.mkdtemp(prefix="fwhost_")
    for kb in (80, 128):
        for pl in (64, 256, 1024):
            ok, rej = run_case(out, kb, pl)
            print(f"  firmware key={kb:3d} payload={pl:4d}B -> receiver menerima {ok} pesan normal  OK")
    ok, rej = run_case(out, 80, 64, tamper_every=3)
    assert rej >= 1
    print(f"  demo tampered firmware: {ok} normal diterima, {rej} tampered ditolak (tag_mismatch)  OK")
    syntax_check_mqtt(out)
    print("  syntax-check varian MQTT (stub) OK")
    print("FIRMWARE-HOST TEST PASSED (logika aplikasi; BUKAN uji hardware)")


if __name__ == "__main__":
    main()
