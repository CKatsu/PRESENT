"""
tools/verify_capture.py
========================
Verifikasi tambahan kerangka (Tabel 2 #11, bagian 7): membuktikan bahwa data yang
melintas di jaringan/kabel benar-benar CIPHERTEXT dan tidak terbaca sebagai teks asli.

Dua sumber capture (keduanya diproses dengan logika pemeriksaan yang sama):
  --pcap  berkas Wireshark/Npcap (.pcap atau .pcapng), mis. capture loopback Npcap
          pada port broker 1883 (MQTT) atau port TCP pengganti UART.
  --raw   berkas byte-di-kabel apa adanya, mis. hasil `device_sim.py --wire-tap FILE`
          (jalur UART/serial tidak bisa di-capture Wireshark biasa) atau log sniffer serial.

Pemeriksaan:
  1. Ekstraksi paket envelope terenkripsi (JSON berisi "ct" & "tag") dari aliran byte.
  2. Tidak ada pola PLAINTEXT sensor di aliran mentah (mis. "t":28.51,"h":..., "q":12,"t":).
  3. Tidak ada pola plaintext di dalam ciphertext yang sudah di-decode base64.
  4. Tidak ada blok ciphertext 8-byte yang berulang dalam satu paket (tanda mode ECB /
     kebocoran struktur; payload 1024 B berisi padding spasi -> uji yang tajam untuk CBC).
  5. Entropi Shannon ciphertext gabungan (bila >= 4096 byte terkumpul) mendekati 8 bit/byte.
  6. KONTROL POSITIF otomatis: paket TIDAK terenkripsi buatan harus DIDETEKSI sebagai bocor
     (membuktikan pemeriksa tidak sekadar selalu bilang lulus).

Catatan jujur: header/topik MQTT dan field envelope (device_id, seq, scenario, IV, tag)
memang terlihat sebagai teks -- itu metadata, bukan payload sensor. Yang harus tidak
terbaca adalah isi sensor (suhu/kelembapan/tekanan) di dalam `ct`.

Contoh:
  python3 tools/verify_capture.py --pcap capture.pcapng
  python3 tools/verify_capture.py --raw results/wire_uart.log
  python3 tools/verify_capture.py --selftest
"""

from __future__ import annotations

import argparse
import base64
import collections
import json
import math
import os
import re
import struct
import sys

ENVELOPE_RE = re.compile(rb'\{[^{}]*"ct":"[A-Za-z0-9+/=]*"[^{}]*\}')
# pola PLAINTEXT sensor (format payload_format.py): {"id":"d001","q":12,"t":28.51,"h":64.2,"p":1009.3,"s":1}
PLAINTEXT_PATTERNS = [
    re.compile(rb'"t":-?\d+\.\d\d,"h":\d+\.\d'),
    re.compile(rb'"q":\d+,"t":'),
    re.compile(rb'"p":\d{3,4}\.\d,"s":[01]'),
    re.compile(rb'\{"id":"d\d{3}"'),
]


# ---------------------------------------------------------------------------
# Pembaca pcap / pcapng minimal
# ---------------------------------------------------------------------------
def _iter_pcap(data: bytes):
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    else:
        raise ValueError("bukan pcap klasik")
    linktype = struct.unpack(end + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        yield linktype, data[off:off + incl]
        off += incl


def _iter_pcapng(data: bytes):
    off, end, links = 0, "<", []
    while off + 12 <= len(data):
        btype = struct.unpack("<I", data[off:off + 4])[0]
        if btype == 0x0A0D0D0A:                                   # SHB: deteksi endianness
            end = "<" if data[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
        btype, blen = struct.unpack(end + "II", data[off:off + 8])
        body = data[off + 8:off + blen - 4]
        if btype == 1:                                            # IDB
            links.append(struct.unpack(end + "H", body[:2])[0])
        elif btype == 6:                                          # EPB
            iface, _, _, caplen, _ = struct.unpack(end + "IIIII", body[:20])
            yield (links[iface] if iface < len(links) else 1), body[20:20 + caplen]
        elif btype == 3:                                          # SPB
            olen = struct.unpack(end + "I", body[:4])[0]
            yield (links[0] if links else 1), body[4:4 + olen]
        if blen < 12:
            break
        off += blen


def _tcp_payload(linktype: int, pkt: bytes):
    """Return (flow_key, payload) atau None."""
    if linktype == 0:                       # BSD loopback (Npcap loopback): 4 byte family
        pkt = pkt[4:]
    elif linktype == 1:                     # Ethernet
        et = struct.unpack(">H", pkt[12:14])[0]
        pkt = pkt[14:]
        if et == 0x8100:
            pkt = pkt[4:]
    elif linktype == 113:                   # Linux cooked
        pkt = pkt[16:]
    elif linktype not in (101, 12, 14):     # RAW IP
        return None
    if not pkt:
        return None
    ver = pkt[0] >> 4
    if ver == 4:
        ihl = (pkt[0] & 0xF) * 4
        if pkt[9] != 6:
            return None
        src, dst, ip_payload = pkt[12:16], pkt[16:20], pkt[ihl:struct.unpack(">H", pkt[2:4])[0]]
    elif ver == 6:
        if pkt[6] != 6:
            return None
        src, dst, ip_payload = pkt[8:24], pkt[24:40], pkt[40:40 + struct.unpack(">H", pkt[4:6])[0]]
    else:
        return None
    if len(ip_payload) < 20:
        return None
    sport, dport = struct.unpack(">HH", ip_payload[:4])
    doff = (ip_payload[12] >> 4) * 4
    return (src, sport, dst, dport), ip_payload[doff:]


def read_pcap_streams(path: str) -> dict:
    data = open(path, "rb").read()
    it = _iter_pcapng(data) if data[:4] == b"\x0a\x0d\x0d\x0a" else _iter_pcap(data)
    streams: dict = collections.defaultdict(bytearray)
    for linktype, pkt in it:
        r = _tcp_payload(linktype, pkt)
        if r and r[1]:
            streams[r[0]].extend(r[1])
    return {k: bytes(v) for k, v in streams.items()}


# ---------------------------------------------------------------------------
# Pemeriksaan
# ---------------------------------------------------------------------------
def entropy_bits_per_byte(b: bytes) -> float:
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def analyze_stream_bytes(blobs: list[bytes]) -> dict:
    res = {"envelopes": 0, "plaintext_hits_raw": 0, "plaintext_hits_ct": 0, "ecb_like_packets": 0,
           "ct_total_bytes": 0, "entropy_bits_per_byte": None, "sample": None, "problems": []}
    ct_all = bytearray()
    for blob in blobs:
        for pat in PLAINTEXT_PATTERNS:
            hits = len(pat.findall(blob))
            if hits:
                res["plaintext_hits_raw"] += hits
        for m in ENVELOPE_RE.finditer(blob):
            try:
                env = json.loads(m.group(0))
                ct = base64.b64decode(env["ct"])
            except (ValueError, KeyError):
                continue
            res["envelopes"] += 1
            if res["sample"] is None:
                res["sample"] = {k: (v[:24] + "…" if isinstance(v, str) and len(v) > 24 else v)
                                 for k, v in env.items() if k in ("device_id", "seq", "key_bits", "iv", "ct", "tag")}
            for pat in PLAINTEXT_PATTERNS:
                res["plaintext_hits_ct"] += len(pat.findall(ct))
            blocks = [ct[i:i + 8] for i in range(0, len(ct) - len(ct) % 8, 8)]
            if len(blocks) > 4 and len(set(blocks)) < len(blocks):
                res["ecb_like_packets"] += 1
            ct_all.extend(ct)
    res["ct_total_bytes"] = len(ct_all)
    if len(ct_all) >= 4096:
        res["entropy_bits_per_byte"] = round(entropy_bits_per_byte(bytes(ct_all)), 4)
    if res["envelopes"] == 0:
        res["problems"].append("tidak ada paket envelope terenkripsi ditemukan (filter/port salah, atau capture kosong)")
    if res["plaintext_hits_raw"]:
        res["problems"].append(f"{res['plaintext_hits_raw']} pola plaintext sensor terbaca di aliran mentah")
    if res["plaintext_hits_ct"]:
        res["problems"].append(f"{res['plaintext_hits_ct']} pola plaintext terbaca di dalam ciphertext")
    if res["ecb_like_packets"]:
        res["problems"].append(f"{res['ecb_like_packets']} paket punya blok ciphertext berulang (mirip ECB)")
    if res["entropy_bits_per_byte"] is not None and res["entropy_bits_per_byte"] < 7.5:
        res["problems"].append(f"entropi ciphertext rendah ({res['entropy_bits_per_byte']} bit/byte)")
    res["verdict"] = "PASS" if not res["problems"] else "FAIL"
    return res


def positive_control() -> bool:
    """Paket TIDAK terenkripsi buatan HARUS terdeteksi bocor (verdict FAIL)."""
    plain = b'{"id":"d001","q":12,"t":28.51,"h":64.2,"p":1009.3,"s":1}'
    env = {"device_id": "d001", "seq": 12, "key_bits": 80, "iv": "00" * 8,
           "ct": base64.b64encode(plain).decode(), "tag": base64.b64encode(b"\0" * 8).decode()}
    blob = b"PRS1:" + json.dumps(env, separators=(",", ":")).encode() + b"\n"
    return analyze_stream_bytes([blob])["verdict"] == "FAIL"


def encrypted_control() -> dict:
    """Paket terenkripsi sungguhan (crypto_utils) HARUS lulus."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import config
    import crypto_utils as cu
    import payload_format as pf
    ks = cu.KeySet.from_bytes(config.KEYS[80]["enc"], config.KEYS[80]["mac"])
    sensor = pf.SyntheticSensor(seed=1)
    blobs = []
    for i in range(40):
        pt = pf.build_payload("d001", i, sensor.read(), 1024 if i % 2 else 64)
        iv = bytes([i]) * 8
        ct, tag = cu.seal(ks, iv, pt)
        env = {"device_id": "d001", "seq": i, "key_bits": 80, "iv": iv.hex(),
               "ct": base64.b64encode(ct).decode(), "tag": base64.b64encode(tag).decode()}
        blobs.append(b"PRS1:" + json.dumps(env, separators=(",", ":")).encode() + b"\n")
    return analyze_stream_bytes(blobs)


def report(name: str, res: dict) -> None:
    print(f"\n== {name} ==")
    print(f"  paket envelope ditemukan     : {res['envelopes']}")
    print(f"  total byte ciphertext        : {res['ct_total_bytes']}")
    print(f"  entropi ciphertext (bit/byte): {res['entropy_bits_per_byte'] if res['entropy_bits_per_byte'] is not None else 'n/a (<4096 B)'}")
    print(f"  pola plaintext di aliran     : {res['plaintext_hits_raw']}   di dalam ciphertext: {res['plaintext_hits_ct']}")
    print(f"  paket mirip-ECB              : {res['ecb_like_packets']}")
    if res["sample"]:
        print(f"  contoh paket (dipotong)      : {res['sample']}")
    for p in res["problems"]:
        print(f"  ! {p}")
    print(f"  HASIL: {res['verdict']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap")
    ap.add_argument("--raw")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)

    ok_neg = positive_control()
    print(f"Kontrol positif (paket plaintext harus terdeteksi bocor): {'OK' if ok_neg else 'GAGAL -- pemeriksa tidak valid'}")
    if not ok_neg:
        return 2
    ctl = encrypted_control()
    report("Kontrol terenkripsi (crypto_utils, 40 paket)", ctl)
    if a.selftest:
        return 0 if ctl["verdict"] == "PASS" else 1
    if not (a.pcap or a.raw):
        ap.error("pilih --pcap, --raw, atau --selftest")
    code = 0
    if a.pcap:
        streams = read_pcap_streams(a.pcap)
        print(f"\nAliran TCP di {os.path.basename(a.pcap)}: {len(streams)}")
        res = analyze_stream_bytes(list(streams.values()))
        report(f"capture {os.path.basename(a.pcap)}", res)
        code |= res["verdict"] != "PASS"
    if a.raw:
        res = analyze_stream_bytes([open(a.raw, "rb").read()])
        report(f"raw {os.path.basename(a.raw)}", res)
        code |= res["verdict"] != "PASS"
    return int(code)


if __name__ == "__main__":
    sys.exit(main())
