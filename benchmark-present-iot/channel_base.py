"""
channel_base.py
================
Antarmuka seragam untuk semua jalur komunikasi (UART, TCP-pengganti-UART, MQTT)
+ framing pesan + "tap" log byte-di-kabel (untuk verifikasi ciphertext).

Kedua peran memakai antarmuka yang sama supaya perbandingan UART vs MQTT adil
(perbedaan hanya pada transport, bukan pada logika aplikasi):

  Peran DEVICE   : send_data(env)            -> kirim paket terenkripsi
                   set_ack_callback(fn)      -> fn(ack: dict) dipanggil (dari thread
                                                pembaca) tiap ACK tiba; RTT dihitung
                                                pemanggil.
  Peran RECEIVER : recv_data(timeout) -> dict | None
                   send_ack(ack)

Framing UART/TCP: satu pesan = satu baris teks  "PRS1:" + json + "\\n".
Baris tanpa prefix (log boot ESP32, dsb.) diabaikan. MQTT: payload = json yang sama
tanpa prefix (topic sudah membedakan).
"""

from __future__ import annotations

import json
import threading
from abc import ABC, abstractmethod
from typing import Callable, Optional

import config


def encode_line(obj: dict) -> bytes:
    return (config.PROTOCOL_PREFIX + json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


def decode_line(raw: bytes) -> Optional[dict]:
    """None bila bukan baris protokol / JSON korup (dicatat pemanggil sebagai gagal)."""
    text = raw.decode("utf-8", errors="replace").strip()
    if not text.startswith(config.PROTOCOL_PREFIX):
        return None
    try:
        obj = json.loads(text[len(config.PROTOCOL_PREFIX):])
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


class WireTap:
    """Menulis SETIAP paket data device->receiver apa adanya (byte persis di kabel,
    satu paket per baris) ke file -- bahan verifikasi 'yang lewat hanya ciphertext'
    untuk jalur serial yang tidak bisa di-capture Wireshark (lihat tools/verify_capture.py)."""

    def __init__(self, path: str):
        self._f = open(path, "ab")
        self._lock = threading.Lock()

    def write(self, payload: bytes) -> None:
        with self._lock:
            self._f.write(payload.rstrip(b"\n") + b"\n")
            self._f.flush()

    def close(self) -> None:
        self._f.close()


class Channel(ABC):
    name = "abstract"     # "uart" | "mqtt"  (jalur LOGIS yang diuji)
    link = "abstract"     # implementasi fisik/virtual: "serial" | "tcp-loopback" | "mqtt-broker"

    def __init__(self, wire_tap: Optional[WireTap] = None):
        self.wire_tap = wire_tap
        self._ack_cb: Optional[Callable[[dict], None]] = None

    def set_ack_callback(self, fn: Callable[[dict], None]) -> None:
        self._ack_cb = fn

    @abstractmethod
    def connect(self) -> None: ...

    @abstractmethod
    def close(self) -> None: ...

    @abstractmethod
    def send_data(self, env: dict) -> int:
        """Kirim paket; return jumlah byte yang ditulis ke kabel/broker."""

    @abstractmethod
    def recv_data(self, timeout_s: float) -> Optional[dict]: ...

    @abstractmethod
    def send_ack(self, ack: dict) -> None: ...

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()
