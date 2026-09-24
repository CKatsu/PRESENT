"""
receiver_server.py
===================
Penerima UART & MQTT (Tabel 1 kerangka): menerima paket terenkripsi, memverifikasi
tag PRESENT-CBC-MAC, mendekripsi PRESENT-CBC, menyimpan data valid, dan mencatat
log verifikasi. Sesuai fase 3.1, receiver dapat aktif pada DUA jalur sekaligus.

Urutan pemrosesan tiap paket (encrypt-then-MAC, verifikasi DULU baru dekripsi):
  1. parse envelope  -> 2. cek key_bits/panjang  -> 3. verifikasi tag (diukur)
  -> 4. dekripsi + unpad (diukur) -> 5. parse JSON sensor -> 6. KIRIM ACK
  -> 7. persist (SQLite + CSV) lewat thread penulis terpisah.
Persistensi sengaja di luar jalur kritis ACK agar RTT tidak tercampur waktu
I/O disk (yang diukur adalah kripto + transport + pemrosesan receiver).

Envelope paket (JSON):
  {"device_id","seq","scenario","condition","tv","run_id","key_bits",
   "iv":<16 hex>,"ct":<base64>,"tag":<base64 8 byte>,"enc_us":<opsional>}
`condition`/`tv` = label ground-truth dari pengirim HANYA untuk menghitung
detection rate / false rejection rate -- TIDAK dipakai untuk memutuskan
menerima/menolak (keputusan murni dari verifikasi tag).

ACK: {"ack":1,"device_id","seq","run_id","accepted","reason","vs","ds",
      "rx_cpu_s","rx_rss_mb"}

Contoh:
  python3 receiver_server.py --tcp-port 9999 --mqtt            # UART-pengganti + MQTT
  python3 receiver_server.py --uart-port COM5 --mqtt           # ESP32-S3 asli + MQTT
"""

from __future__ import annotations

import argparse
import base64
import binascii
import collections
import logging
import queue
import sqlite3
import sys
import threading
import time
from typing import Optional

import config
import crypto_utils as cu
import metrics
import payload_format as pf
from mqtt_channel import MqttChannel
from uart_channel import TcpChannel, UartChannel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [receiver] %(levelname)s %(message)s")
log = logging.getLogger("receiver")

SCHEMA = """
CREATE TABLE IF NOT EXISTS valid_readings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL, seq INTEGER NOT NULL, scenario TEXT,
    transport TEXT, link TEXT, key_bits INTEGER,
    received_at_unix REAL NOT NULL,
    temp_c REAL, hum_pct REAL, pres_hpa REAL,
    is_synthetic_sensor INTEGER NOT NULL,      -- 1 = sintetis, 0 = sensor fisik
    payload_bytes INTEGER
);
CREATE TABLE IF NOT EXISTS verification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT, seq INTEGER, scenario TEXT, transport TEXT, link TEXT, key_bits INTEGER,
    condition_label TEXT, tamper_variant TEXT,
    accepted INTEGER NOT NULL, reason TEXT,
    verify_s REAL, decrypt_s REAL, received_at_unix REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_valid_time ON valid_readings(received_at_unix);
CREATE INDEX IF NOT EXISTS idx_log_scn ON verification_log(scenario, transport);
"""


def init_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


class AsyncWriter:
    """Thread penulis: menampung record dari jalur kritis lalu menulis ke SQLite/CSV
    secara batch. Data tidak hilang saat berhenti: stop() menguras antrean."""

    def __init__(self, conn: sqlite3.Connection, csv_logger: metrics.CsvLogger):
        self.conn, self.csv = conn, csv_logger
        self.q: "queue.Queue" = queue.Queue()
        self._thread = threading.Thread(target=self._run, name="writer", daemon=True)
        self._done = threading.Event()

    def start(self):
        self._thread.start()

    def put(self, server_rec: metrics.ServerRecord, valid_row: Optional[tuple]):
        self.q.put((server_rec, valid_row))

    def _flush(self, batch):
        if not batch:
            return
        self.csv.log_many([b[0] for b in batch])
        cur = self.conn.cursor()
        for rec, valid in batch:
            cur.execute(
                "INSERT INTO verification_log (device_id,seq,scenario,transport,link,key_bits,condition_label,"
                "tamper_variant,accepted,reason,verify_s,decrypt_s,received_at_unix) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rec.device_id, rec.seq, rec.scenario, rec.transport, rec.link, rec.key_bits, rec.condition_label,
                 rec.tamper_variant, int(rec.accepted), rec.reason, rec.verify_s, rec.decrypt_s, rec.t_recv_unix))
            if valid is not None:
                cur.execute(
                    "INSERT INTO valid_readings (device_id,seq,scenario,transport,link,key_bits,received_at_unix,"
                    "temp_c,hum_pct,pres_hpa,is_synthetic_sensor,payload_bytes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", valid)
        self.conn.commit()

    def _run(self):
        while True:
            batch = []
            try:
                batch.append(self.q.get(timeout=0.5))
                while len(batch) < 500:
                    batch.append(self.q.get_nowait())
            except queue.Empty:
                pass
            self._flush(batch)
            if not batch and self._done.is_set():
                return

    def stop(self):
        self._done.set()
        self._thread.join(timeout=30)


class Receiver:
    def __init__(self, writer: Optional[AsyncWriter], monitor: Optional[metrics.ResourceMonitor]):
        self.keysets = {kb: cu.KeySet.from_bytes(k["enc"], k["mac"]) for kb, k in config.KEYS.items()}
        self.writer, self.monitor = writer, monitor
        self._lock = threading.Lock()                # 1 gateway = 1 pemroses (model penerima tunggal)
        self._seen: "collections.OrderedDict" = collections.OrderedDict()   # dedupe (QoS1 bisa duplikat)
        self.processed = 0
        self._last = (None, 0, 0)

    def handle(self, msg: dict, transport: str, link: str) -> dict:
        with self._lock:
            return self._handle(msg, transport, link)

    def handle_detailed(self, msg: dict, transport: str, link: str):
        """Seperti handle(), tetapi juga mengembalikan (ack, reading, key_bits, ct_len) untuk log per pesan."""
        with self._lock:
            self._last = (None, 0, 0)
            ack = self._handle(msg, transport, link)
            reading, key_bits, ct_len = self._last
            return ack, reading, key_bits, ct_len

    def _handle(self, msg: dict, transport: str, link: str) -> dict:
        device_id = str(msg.get("device_id", "unknown"))
        try:
            seq = int(msg.get("seq", -1))
        except (TypeError, ValueError):
            seq = -1
        scenario = str(msg.get("scenario", "UNSPEC"))
        run_id = str(msg.get("run_id", ""))
        dedupe_key = (transport, device_id, run_id, scenario, seq)
        if run_id and dedupe_key in self._seen:
            return self._seen[dedupe_key]                       # duplikat: ACK ulang, tidak dicatat

        accepted, reason = False, "ok"
        verify_s = decrypt_s = None
        pt_len = None
        reading = None
        key_bits, ct_len = 0, 0
        try:
            key_bits = int(msg["key_bits"])
            iv = bytes.fromhex(msg["iv"])
            ct = base64.b64decode(msg["ct"], validate=True)
            tag = base64.b64decode(msg["tag"], validate=True)
            ct_len = len(ct)
        except (KeyError, ValueError, TypeError, binascii.Error):
            reason = "malformed"
        else:
            ks = self.keysets.get(key_bits)
            if ks is None:
                reason = "unknown_key_bits"
            elif len(iv) != cu.IV_BYTES or not ct or len(ct) % 8 or len(tag) != cu.TAG_BYTES:
                reason = "bad_length"
            else:
                with metrics.timed() as t_v:
                    tag_ok = cu.verify_tag(ks.mac, iv, ct, tag)
                verify_s = t_v.elapsed_s
                if not tag_ok:
                    reason = "tag_mismatch"
                else:
                    try:
                        with metrics.timed() as t_d:
                            plaintext = cu.cbc_decrypt(ks.enc, iv, ct)
                        decrypt_s = t_d.elapsed_s
                        pt_len = len(plaintext)
                        reading = pf.parse_payload(plaintext)
                        accepted = True
                    except cu.PaddingError:
                        reason = "padding_error"
                    except (ValueError, KeyError, UnicodeDecodeError):
                        reason = "payload_error"

        self._last = (reading, key_bits, ct_len)
        cpu_s = metrics.cpu_time_s()
        rss = self.monitor.latest()[1] if self.monitor else 0.0
        ack = {"ack": 1, "device_id": device_id, "seq": seq, "run_id": run_id, "accepted": accepted,
               "reason": reason, "vs": verify_s, "ds": decrypt_s,
               "rx_cpu_s": round(cpu_s, 6), "rx_rss_mb": round(rss, 3)}
        if run_id:
            self._seen[dedupe_key] = ack
            if len(self._seen) > 200_000:
                self._seen.popitem(last=False)

        if scenario != "WARMUP" and self.writer is not None:       # warmup: diverifikasi, TIDAK dicatat
            now = time.time()
            rec = metrics.ServerRecord(
                scenario=scenario, transport=transport, link=link, key_bits=key_bits, device_id=device_id,
                seq=seq, condition_label=str(msg.get("condition", "")), tamper_variant=str(msg.get("tv", "")),
                ciphertext_bytes=ct_len, accepted=accepted, reason=reason, verify_s=verify_s, decrypt_s=decrypt_s,
                plaintext_bytes=pt_len, rx_cpu_s=cpu_s, rx_rss_mb=rss,
                is_synthetic_sensor=(reading["synthetic"] if reading else None),
                device_enc_us=(int(msg["enc_us"]) if str(msg.get("enc_us", "")).isdigit() else None),
                t_recv_unix=now)
            valid = None
            if accepted and reading is not None:
                valid = (device_id, seq, scenario, transport, link, key_bits, now, reading["temp_c"],
                         reading["hum_pct"], reading["pres_hpa"], 1 if reading["synthetic"] else 0, pt_len)
            self.writer.put(rec, valid)
        self.processed += 1
        return ack


class ReceiverService:
    """Menjalankan satu thread listener per channel (uart/tcp/mqtt). Dapat dipakai
    dari CLI maupun in-process (tests)."""

    def __init__(self, channels, receiver: Receiver, verbose: bool = True):
        self.channels, self.receiver, self.verbose = channels, receiver, verbose
        self._stop = threading.Event()
        self._threads = []
        self._ready = {id(c): threading.Event() for c in channels}

    @staticmethod
    def _format_result(msg, ack, reading, key_bits, ct_len) -> str:
        head = (f"device={ack['device_id']} seq={ack['seq']} scenario={msg.get('scenario', '-')} "
                f"key={key_bits or msg.get('key_bits', '?')}bit ct={ct_len}B")
        if ack["accepted"]:
            data = ""
            if reading is not None:
                data = (f" temp={reading['temp_c']:.2f}C hum={reading['hum_pct']:.1f}% "
                        f"pres={reading['pres_hpa']:.1f}hPa "
                        f"[{'SINTETIS' if reading['synthetic'] else 'SENSOR FISIK'}]")
            enc = f" enc_fw={msg['enc_us']}us" if str(msg.get("enc_us", "")).isdigit() else ""
            return f"Pesan DITERIMA  {head}{data}{enc}"
        return f"Pesan DITOLAK    {head} alasan={ack['reason']} (condition={msg.get('condition', '-')})"

    def _listen(self, ch):
        try:
            with ch:
                self._ready[id(ch)].set()
                log.info("Listener aktif: jalur=%s link=%s", ch.name, ch.link)
                last_note = time.monotonic()
                shown = 0
                while not self._stop.is_set():
                    t0 = time.monotonic()
                    msg = ch.recv_data(0.5)
                    if msg is None:
                        if time.monotonic() - t0 < 0.1:
                            time.sleep(0.1)                 # hindari busy-loop bila lawan bicara putus
                        # diagnostik: tiap 5 dtk tanpa paket valid, laporkan apa yang sebenarnya masuk dari port
                        if hasattr(ch, "bytes_rx") and self.receiver.processed == 0 \
                                and time.monotonic() - last_note >= 5.0:
                            last_note = time.monotonic()
                            log.info("[%s] belum ada paket PRS1 valid | byte diterima dari port: %d | "
                                     "baris non-protokol: %d%s", ch.name, ch.bytes_rx, ch.lines_other,
                                     "  -> port tidak mengirim apa pun (cek port/kabel/firmware)"
                                     if ch.bytes_rx == 0 else
                                     "  -> ada data tapi bukan format PRS1 (coba --show-raw, cek baud)")
                        continue
                    ack, reading, key_bits, ct_len = self.receiver.handle_detailed(msg, ch.name, ch.link)
                    if self.verbose:
                        log.info("%s", self._format_result(msg, ack, reading, key_bits, ct_len))
                    else:                                    # mode ringkas: cetak 10 pertama lalu tiap 50 pesan
                        shown += 1
                        if shown <= 10 or shown % 50 == 0:
                            log.info("%s", self._format_result(msg, ack, reading, key_bits, ct_len))
                    try:
                        ch.send_ack(ack)
                    except Exception as exc:               # noqa: BLE001
                        log.warning("Gagal kirim ACK (%s): %s", ch.name, exc)
        except Exception as exc:                            # noqa: BLE001
            log.error("Listener %s berhenti karena error: %s", ch.name, exc)
            self._ready[id(ch)].set()

    def start(self):
        for ch in self.channels:
            t = threading.Thread(target=self._listen, args=(ch,), name=f"listen-{ch.name}-{ch.link}", daemon=True)
            t.start()
            self._threads.append(t)

    def wait_ready(self, timeout: float = 15.0) -> bool:
        return all(e.wait(timeout) for e in self._ready.values())

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(timeout=3.0)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--uart-port", default=None, help="port serial ESP32 (COM5, /dev/ttyACM0) atau URL pyserial")
    p.add_argument("--baud", type=int, default=config.UART_BAUDRATE)
    p.add_argument("--tcp-port", type=int, default=None, help="pengganti UART tanpa driver (TCP loopback)")
    p.add_argument("--mqtt", action="store_true", help="aktifkan jalur MQTT (butuh broker Mosquitto)")
    p.add_argument("--mqtt-host", default=config.MQTT_HOST)
    p.add_argument("--mqtt-port", type=int, default=config.MQTT_PORT)
    p.add_argument("--db-path", default=config.DB_PATH)
    p.add_argument("--csv-name", default="all", help="nama berkas results/server_<name>.csv")
    p.add_argument("--no-monitor", action="store_true")
    p.add_argument("--show-raw", action="store_true",
                   help="tampilkan baris non-protokol dari port (mis. log boot firmware) sebagai '[fw] ...'")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--verbose", action="store_true", help="cetak SETIAP pesan yang diproses")
    g.add_argument("--quiet", action="store_true", help="ringkas: 10 pesan pertama lalu tiap 50 pesan")
    # Default: hanya --uart-port (uji hardware) -> verbose; bila ada --tcp-port/--mqtt (benchmark) -> ringkas,
    # karena log per pesan memakai CPU/IO receiver dan akan memengaruhi pengukuran CPU% & RTT.
    return p


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    channels = []
    if args.uart_port:
        channels.append(UartChannel("receiver", port=args.uart_port, baudrate=args.baud))
    if args.tcp_port:
        channels.append(TcpChannel("receiver", port=args.tcp_port))
    if args.mqtt:
        channels.append(MqttChannel("receiver", host=args.mqtt_host, port=args.mqtt_port))
    if not channels:
        sys.exit("Pilih minimal satu jalur: --uart-port / --tcp-port / --mqtt")

    conn = init_db(args.db_path)
    csv_path = config.metrics_csv_path("server", args.csv_name)
    writer = AsyncWriter(conn, metrics.CsvLogger(csv_path, metrics.ServerRecord))
    writer.start()
    monitor = None
    if not args.no_monitor:
        monitor = metrics.ResourceMonitor("receiver", config.metrics_csv_path("resources", "receiver"),
                                          config.RESOURCE_SAMPLING_INTERVAL_S)
        monitor.start()
    if args.show_raw:
        for ch in channels:
            if hasattr(ch, "raw_hook"):
                ch.raw_hook = lambda text: log.info("[fw] %s", text)
    hardware_only = bool(args.uart_port) and not args.tcp_port and not args.mqtt
    verbose = args.verbose or (hardware_only and not args.quiet)
    svc = ReceiverService(channels, Receiver(writer, monitor), verbose=verbose)
    svc.start()
    log.info("receiver_server siap. DB=%s CSV=%s  (Ctrl+C untuk berhenti)", args.db_path, csv_path)
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        log.info("Dihentikan pengguna.")
    finally:
        svc.stop()
        writer.stop()
        if monitor:
            monitor.stop()
        conn.close()
        log.info("Total paket diproses: %d", svc.receiver.processed)


if __name__ == "__main__":
    main()
