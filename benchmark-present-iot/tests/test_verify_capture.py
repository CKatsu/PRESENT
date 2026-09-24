"""
tests/test_verify_capture.py -- menguji tools/verify_capture.py dengan pcap/pcapng SINTETIS
(dibuat di sini, bukan capture Wireshark asli) + berkas wire-tap. Capture Wireshark/Npcap
nyata harus Anda ambil sendiri (lihat README).
"""
import base64
import json
import os
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import config  # noqa: E402
import crypto_utils as cu  # noqa: E402
import payload_format as pf  # noqa: E402
import verify_capture as vc  # noqa: E402


def make_envelopes(encrypted: bool, n=30):
    ks = cu.KeySet.from_bytes(config.KEYS[128]["enc"], config.KEYS[128]["mac"])
    s = pf.SyntheticSensor(seed=3)
    out = []
    for i in range(n):
        pt = pf.build_payload("d002", i, s.read(), 256)
        iv = bytes([i + 1]) * 8
        ct, tag = cu.seal(ks, iv, pt)
        if not encrypted:
            ct = pt
        out.append(json.dumps({"device_id": "d002", "seq": i, "key_bits": 128, "iv": iv.hex(),
                               "ct": base64.b64encode(ct).decode(), "tag": base64.b64encode(tag).decode()},
                              separators=(",", ":")).encode())
    return out


def mqtt_publish(payload: bytes) -> bytes:
    topic = b"present/d002/data"
    body = struct.pack(">H", len(topic)) + topic + struct.pack(">H", 1) + payload
    rl, x = bytearray(), len(body)
    while True:
        b = x % 128
        x //= 128
        rl.append(b | (0x80 if x else 0))
        if not x:
            break
    return bytes([0x32]) + bytes(rl) + body


def eth_ip_tcp(payload: bytes, seq: int) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", 40000, 1883, seq, 0, 5 << 4, 0x18, 65535, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, bytes([127, 0, 0, 1]), bytes([127, 0, 0, 1])) + tcp
    return b"\x00" * 12 + b"\x08\x00" + ip


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for fr in frames:
            f.write(struct.pack("<IIII", 0, 0, len(fr), len(fr)) + fr)


def write_pcapng(path, frames):
    def blk(t, body):
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return struct.pack("<II", t, total) + body + b"\0" * pad + struct.pack("<I", total)
    with open(path, "wb") as f:
        f.write(blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        f.write(blk(1, struct.pack("<HHI", 1, 0, 65535)))
        for fr in frames:
            f.write(blk(6, struct.pack("<IIIII", 0, 0, 0, len(fr), len(fr)) + fr))


def frames_for(envs):
    return [eth_ip_tcp(mqtt_publish(e), 1000 + i * 2000) for i, e in enumerate(envs)]


def test_all():
    assert vc.positive_control(), "kontrol positif harus mendeteksi plaintext"
    assert vc.encrypted_control()["verdict"] == "PASS"
    d = tempfile.mkdtemp()
    for writer, name in ((write_pcap, "a.pcap"), (write_pcapng, "b.pcapng")):
        good, bad = os.path.join(d, "g" + name), os.path.join(d, "b" + name)
        writer(good, frames_for(make_envelopes(True)))
        writer(bad, frames_for(make_envelopes(False)))
        rg = vc.analyze_stream_bytes(list(vc.read_pcap_streams(good).values()))
        rb = vc.analyze_stream_bytes(list(vc.read_pcap_streams(bad).values()))
        assert rg["envelopes"] == 30 and rg["verdict"] == "PASS", (name, rg)
        assert rb["verdict"] == "FAIL" and rb["plaintext_hits_ct"] > 0, (name, rb)
    raw = os.path.join(d, "wire.log")
    open(raw, "wb").write(b"\n".join(b"PRS1:" + e for e in make_envelopes(True)) + b"\n")
    assert vc.main(["--raw", raw]) == 0
    print("verify_capture: pcap, pcapng, raw + kontrol positif/negatif -> PASSED")


if __name__ == "__main__":
    test_all()
