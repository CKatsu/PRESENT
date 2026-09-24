"""
metrics.py
==========
Perekam RTT, waktu kripto, throughput (data mentah), serta CPU & RAM (Tabel 1).

Prinsip (sama dengan proyek SPECK):
  * Waktu kripto (enkripsi, MAC, verifikasi, dekripsi) diukur TERPISAH dari waktu
    pembentukan payload & transmisi, dengan time.perf_counter().
  * RTT diukur di sisi pengirim: sesaat sebelum send_data() sampai ACK diterima.
  * SEMUA hasil mentah per-pesan / per-ronde dicatat ke CSV dulu; statistik
    (mean/SD/CI) baru dihitung di analyze.py.
  * CPU/RAM: (a) ResourceMonitor mencuplik psutil tiap 1 detik (fase 3.1 kerangka)
    ke CSV linimasa mentah; (b) delta waktu-CPU proses per ronde (process_time)
    dicatat pada RoundRecord. CATATAN: resolusi jam CPU di Windows ~15,6 ms, jadi
    persen-CPU per ronde pendek kurang teliti -- analyze.py melaporkan CPU% per
    BLOK (jumlah delta / jumlah waktu ronde) sebagai angka utama.
  * Yang diukur adalah proses sender/receiver di komputer HOST, bukan mikrokontroler.
"""

from __future__ import annotations

import csv
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields
from typing import Optional

try:
    import psutil
except ImportError:                     # pragma: no cover
    psutil = None


@contextmanager
def timed():
    """with timed() as t: ... -> t.elapsed_s (perf_counter, monotonic, resolusi tinggi)."""
    class _T:
        elapsed_s = 0.0
    t = _T()
    start = time.perf_counter()
    try:
        yield t
    finally:
        t.elapsed_s = time.perf_counter() - start


def cpu_time_s() -> float:
    """Waktu CPU (user+system, seluruh thread) proses ini, detik."""
    return time.process_time()


# ---------------------------------------------------------------------------
# Record (skema CSV)
# ---------------------------------------------------------------------------

@dataclass
class MessageRecord:
    """Satu baris per pesan, sisi PENGIRIM (device_sim.py)."""
    session_id: str                   # satu eksekusi device_sim.py = satu sesi (lihat results/run_metadata.json)
    scenario: str
    transport: str                    # jalur logis: uart | mqtt
    link: str                         # serial | tcp-loopback | mqtt-broker
    key_bits: int
    concurrency: int
    payload_bytes: int                # panjang plaintext (sebelum padding)
    round: int                        # indeks pengulangan 0..30 (S4: indeks pesan)
    device_id: str
    seq: int
    condition: str                    # normal | tampered (label ground-truth)
    tamper_variant: str = ""
    ciphertext_bytes: int = 0
    wire_bytes: int = 0
    encrypt_s: Optional[float] = None   # CBC-encrypt saja
    mac_s: Optional[float] = None       # CBC-MAC saja
    rtt_s: Optional[float] = None       # send -> ACK
    e2e_s: Optional[float] = None       # encrypt_s + mac_s + rtt_s
    accepted: Optional[bool] = None     # putusan receiver (dari ACK)
    ack_reason: str = ""
    rx_verify_s: Optional[float] = None
    rx_decrypt_s: Optional[float] = None
    lost: bool = False                  # tidak ada ACK dalam batas waktu
    is_synthetic_sensor: bool = True
    t_send_unix: float = field(default_factory=time.time)


@dataclass
class RoundRecord:
    """Satu baris per ronde (= 1 pengulangan) -- unit statistik n=31."""
    session_id: str
    scenario: str
    transport: str
    link: str
    key_bits: int
    concurrency: int
    payload_bytes: int
    round: int
    n_sent: int
    n_accepted: int
    n_lost: int
    wall_s: float                     # dari sesaat sebelum barrier dilepas sampai ACK terakhir
    plain_bytes_total: int
    tx_cpu_s: float                   # delta waktu-CPU proses sender pada ronde ini
    rx_cpu_s: Optional[float]         # delta waktu-CPU proses receiver (dari ACK)
    rx_wall_s: Optional[float]        # rentang waktu yang dipakai utk delta rx_cpu_s
    tx_rss_mb: float
    rx_rss_mb: Optional[float]
    t_start_unix: float = field(default_factory=time.time)


@dataclass
class ServerRecord:
    """Satu baris per paket, sisi PENERIMA (receiver_server.py)."""
    scenario: str
    transport: str
    link: str
    key_bits: int
    device_id: str
    seq: int
    condition_label: str              # label dari pengirim -- HANYA untuk evaluasi, tidak dipakai memutuskan
    tamper_variant: str
    ciphertext_bytes: int
    accepted: bool
    reason: str
    verify_s: Optional[float]
    decrypt_s: Optional[float]
    plaintext_bytes: Optional[int]
    rx_cpu_s: float                   # kumulatif proses receiver
    rx_rss_mb: float
    is_synthetic_sensor: Optional[bool]
    device_enc_us: Optional[int]      # waktu kripto diukur firmware ESP32 (bila ada)
    t_recv_unix: float = field(default_factory=time.time)


class CsvLogger:
    """Append-only, thread-safe. Header ditulis sekali; boleh dilanjutkan tanpa
    kehilangan data mentah."""

    def __init__(self, path: str, record_cls):
        self.path = path
        self._names = [f.name for f in fields(record_cls)]
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            with open(path, "w", newline="") as f:
                csv.DictWriter(f, fieldnames=self._names).writeheader()

    def log(self, rec) -> None:
        with self._lock, open(self.path, "a", newline="") as f:
            csv.DictWriter(f, fieldnames=self._names).writerow(asdict(rec))

    def log_many(self, recs) -> None:
        with self._lock, open(self.path, "a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=self._names)
            for r in recs:
                w.writerow(asdict(r))


# ---------------------------------------------------------------------------
# Pemantau sumber daya (psutil, tiap 1 detik) -> CSV linimasa mentah
# ---------------------------------------------------------------------------

class ResourceMonitor:
    def __init__(self, role: str, csv_path: Optional[str] = None, interval_s: float = 1.0):
        if psutil is None:
            raise RuntimeError("psutil belum terpasang: pip install psutil")
        self.role, self.interval_s = role, interval_s
        self._proc = psutil.Process(os.getpid())
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._latest = (0.0, self._proc.memory_info().rss / 1048576)
        self._writer_path = csv_path
        self._lock = threading.Lock()

    def _run(self):
        self._proc.cpu_percent(None)                       # panggilan pertama = baseline
        f = None
        w = None
        if self._writer_path:
            new = not os.path.exists(self._writer_path) or os.path.getsize(self._writer_path) == 0
            f = open(self._writer_path, "a", newline="")
            w = csv.writer(f)
            if new:
                w.writerow(["t_unix", "role", "cpu_percent", "rss_mb"])
        try:
            while not self._stop.wait(self.interval_s):
                cpu = self._proc.cpu_percent(None)
                rss = self._proc.memory_info().rss / 1048576
                with self._lock:
                    self._latest = (cpu, rss)
                if w:
                    w.writerow([f"{time.time():.3f}", self.role, cpu, f"{rss:.3f}"])
                    f.flush()
        finally:
            if f:
                f.close()

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name=f"resmon-{self.role}", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3.0)

    def rss_mb(self) -> float:
        """RSS saat ini (baca langsung -- murah, tidak menunggu siklus 1 detik)."""
        return self._proc.memory_info().rss / 1048576

    def latest(self) -> tuple[float, float]:
        with self._lock:
            return self._latest
