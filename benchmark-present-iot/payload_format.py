"""
payload_format.py
==================
Payload sensor (JSON ringkas) + sumber data sensor.

Kerangka (Tabel 1, device_sim.py): data sensor dalam format JSON dengan ukuran
payload bertingkat (64/256/1024 byte). Ukuran = panjang PLAINTEXT sebelum
padding kriptografi. Agar ukuran persis sama tiap pengulangan (prinsip fairness
bagian 1 kerangka), JSON ringkas di-padding dengan spasi di belakang sampai
mencapai ukuran target (spasi setelah '}' tetap JSON valid).

Layout (kunci sengaja pendek supaya tier 64 byte muat):
    {"id":"d001","q":12,"t":28.51,"h":64.2,"p":1009.3,"s":1}
    id = ID perangkat, q = nomor urut, t = suhu (C), h = kelembapan (%RH),
    p = tekanan (hPa), s = 1 jika data SINTETIS, 0 jika dari sensor fisik.

Catatan DEVIASI dari kerangka (dicatat di README "Keputusan desain"): kerangka
menyebut (suhu, kelembaban, cahaya). GY-BME280 tidak punya sensor cahaya, jadi
kanal ketiga = tekanan (hPa) yang memang diukur BME280.

Firmware (esp32-firmware/src/payload.cpp) menghasilkan format IDENTIK.

Peralihan sintetis -> sensor fisik: semua pembaca sensor mengimplementasikan
`SensorSource.read() -> Reading`. Di firmware ESP32 peralihan otomatis
(BME280 terdeteksi -> s=0). Di Python (device_sim) cukup menambah kelas baru
dengan read() yang sama; struktur payload/CSV/DB tidak berubah.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass

import config


@dataclass
class Reading:
    temp_c: float
    hum_pct: float
    pres_hpa: float
    synthetic: bool          # SELALU diisi jujur; tidak boleh menyamar sebagai sensor asli


class SensorSource:
    """Antarmuka sumber sensor. Implementasi: SyntheticSensor (sekarang),
    sensor fisik (nanti)."""

    def read(self) -> Reading:  # pragma: no cover - antarmuka
        raise NotImplementedError


class SyntheticSensor(SensorSource):
    """Random-walk suhu/kelembapan/tekanan (bukan angka independen) agar pola
    mirip sensor sungguhan. Rentang = ASUMSI simulasi (config.py), bukan
    kalibrasi terhadap BME280 nyata."""

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(config.SENSOR_SEED if seed is None else seed)
        self.t = config.SYN_TEMP_BASE_C
        self.h = config.SYN_HUM_BASE_PCT
        self.p = config.SYN_PRES_BASE_HPA

    @staticmethod
    def _clamp(v, base, jit):
        return min(max(v, base - jit), base + jit)

    def read(self) -> Reading:
        r = self._rng
        self.t = self._clamp(self.t + r.uniform(-0.15, 0.15), config.SYN_TEMP_BASE_C, config.SYN_TEMP_JITTER_C)
        self.h = self._clamp(self.h + r.uniform(-0.8, 0.8), config.SYN_HUM_BASE_PCT, config.SYN_HUM_JITTER_PCT)
        self.p = self._clamp(self.p + r.uniform(-0.1, 0.1), config.SYN_PRES_BASE_HPA, config.SYN_PRES_JITTER_HPA)
        return Reading(round(self.t, 2), round(self.h, 1), round(self.p, 1), True)


def build_payload(device_id: str, seq: int, reading: Reading, target_size: int) -> bytes:
    """JSON ringkas + padding spasi sampai TEPAT `target_size` byte."""
    body = (f'{{"id":"{device_id}","q":{seq},"t":{reading.temp_c:.2f},"h":{reading.hum_pct:.1f},'
            f'"p":{reading.pres_hpa:.1f},"s":{1 if reading.synthetic else 0}}}').encode("ascii")
    if len(body) > target_size:
        raise ValueError(f"payload minimal {len(body)} byte > target {target_size} byte")
    return body + b" " * (target_size - len(body))


def parse_payload(plaintext: bytes) -> dict:
    """Raise ValueError bila bukan JSON valid / field wajib hilang."""
    obj = json.loads(plaintext.decode("ascii"))
    return {
        "device_id": str(obj["id"]),
        "seq": int(obj["q"]),
        "temp_c": float(obj["t"]),
        "hum_pct": float(obj["h"]),
        "pres_hpa": float(obj["p"]),
        "synthetic": bool(int(obj["s"])),
    }
