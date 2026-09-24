"""
device_sim.py
==============
Simulator perangkat IoT (Tabel 1): membangkitkan data sensor SINTETIS (suhu,
kelembapan, tekanan) dalam JSON dengan ukuran payload bertingkat, mengenkripsi
(PRESENT-CBC) + menghitung tag (PRESENT-CBC-MAC), lalu mengirim lewat UART atau
MQTT. Menjalankan skenario S1-S4 (Tabel 4) dan mode STREAMING (cek data suhu).

Perangkat konkuren (1/10/50) = thread dalam SATU proses Python (ThreadPoolExecutor).
Yang disimulasikan: 50 node logis yang berbagi satu uplink (UART: satu kabel
dimultipleks; MQTT: satu koneksi klien per node ke broker) -- BUKAN 50 MCU fisik
dan bukan 50 core paralel (GIL). Konsekuensinya dibahas di README (Batasan).

Definisi 1 pengulangan ("ronde"): tiap perangkat mengirim tepat SATU pesan
serentak (barrier), lalu semua ACK ditunggu. 31 ronde per kombinasi parameter,
didahului ronde pemanasan yang tidak dicatat. Data mentah:
  results/device_<S>.csv  (per pesan)   results/runs_<S>.csv (per ronde)

Contoh:
  python3 device_sim.py --scenario all --tcp-port 9999 --transport both
  python3 device_sim.py --scenario S1 --uart-port COM5 --transport uart
  python3 device_sim.py --stream --duration 30 --transport mqtt
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import platform
import random
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import attacker
import channel_base as cb
import config
import crypto_utils as cu
import metrics
import payload_format as pf
from mqtt_channel import MqttChannel
from uart_channel import TcpChannel, UartChannel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [device_sim] %(levelname)s %(message)s")
log = logging.getLogger("device_sim")


# ---------------------------------------------------------------------------
# ACK router: banyak thread menunggu ACK dari satu/lebih channel
# ---------------------------------------------------------------------------
class AckRouter:
    def __init__(self):
        self._w: dict = {}
        self._lock = threading.Lock()

    def register(self, device_id: str, seq: int):
        ev, slot = threading.Event(), [None, None]
        with self._lock:
            self._w[(device_id, seq)] = (ev, slot)
        return ev, slot

    def cancel(self, device_id: str, seq: int):
        with self._lock:
            self._w.pop((device_id, seq), None)

    def on_ack(self, ack: dict):
        t = time.perf_counter()                # waktu kedatangan dicatat di thread pembaca
        with self._lock:
            w = self._w.pop((ack.get("device_id"), ack.get("seq")), None)
        if w:
            ev, slot = w
            slot[0], slot[1] = ack, t
            ev.set()


class SimDevice:
    def __init__(self, index: int, channel: cb.Channel):
        self.index = index
        self.device_id = f"d{index + 1:03d}"
        self.channel = channel
        self.sensor: pf.SensorSource = pf.SyntheticSensor(seed=config.SENSOR_SEED + index)
        self._iv_rng = random.Random(f"{config.IV_SEED}:{self.device_id}")
        self._attack_rng = random.Random(f"attack:{config.IV_SEED}:{self.device_id}")
        self.seq = 0

    def next_iv(self) -> bytes:
        return self._iv_rng.randbytes(cu.IV_BYTES)


class Session:
    """Satu jalur logis (uart/mqtt) dengan `n_devices` perangkat siap kirim."""

    def __init__(self, transport: str, n_devices: int, args, session_id: str):
        self.transport, self.session_id, self.n_devices = transport, session_id, n_devices
        self.router = AckRouter()
        self.keysets = {kb: cu.KeySet.from_bytes(k["enc"], k["mac"]) for kb, k in config.KEYS.items()}
        self.run_id = uuid.uuid4().hex[:8]
        self.tap = cb.WireTap(args.wire_tap) if args.wire_tap else None
        self.channels: list[cb.Channel] = []
        self.devices: list[SimDevice] = []
        self._shared = transport == "uart"
        if self._shared:
            if args.uart_port:
                ch = UartChannel("device", port=args.uart_port, baudrate=args.baud, wire_tap=self.tap)
            else:
                ch = TcpChannel("device", port=args.tcp_port, wire_tap=self.tap)
            self.channels = [ch]
            self.devices = [SimDevice(i, ch) for i in range(n_devices)]
        else:
            for i in range(n_devices):
                dev_id = f"d{i + 1:03d}"
                self.channels.append(MqttChannel("device", device_id=dev_id, host=args.mqtt_host,
                                                 port=args.mqtt_port, wire_tap=self.tap))
            self.devices = [SimDevice(i, self.channels[i]) for i in range(n_devices)]
        self.link = self.channels[0].link
        self.pool = ThreadPoolExecutor(max_workers=max(1, n_devices), thread_name_prefix="dev")
        self._prev_rx: Optional[tuple[float, float]] = None      # (rx_cpu_s, t_arrival) ronde sebelumnya

    def open(self):
        for ch in self.channels:
            ch.set_ack_callback(self.router.on_ack)
            ch.connect()

    def close(self):
        self.pool.shutdown(wait=True)
        for ch in self.channels:
            ch.close()
        if self.tap:
            self.tap.close()

    # ------------------------------------------------------------------ satu pesan
    def send_one(self, dev: SimDevice, *, scenario: str, key_bits: int, payload_bytes: int, round_idx: int,
                 concurrency: int, condition: str = "normal", variant: str = "") -> tuple[metrics.MessageRecord, Optional[float], Optional[dict]]:
        """Return (record, t_ack_arrival_perf, ack_dict)."""
        ks = self.keysets[key_bits]
        reading = dev.sensor.read()
        seq = dev.seq
        dev.seq += 1
        plaintext = pf.build_payload(dev.device_id, seq, reading, payload_bytes)
        iv = dev.next_iv()

        with metrics.timed() as t_enc:                                   # murni CBC-encrypt (+padding)
            ct = cu.cbc_encrypt(ks.enc, iv, plaintext)
        with metrics.timed() as t_mac:                                   # murni CBC-MAC
            tag = cu.cbc_mac(ks.mac, cu.mac_input(iv, ct))

        env = {"device_id": dev.device_id, "seq": seq, "scenario": scenario, "condition": "normal", "tv": "",
               "run_id": self.run_id, "key_bits": key_bits, "iv": iv.hex(),
               "ct": base64.b64encode(ct).decode("ascii"), "tag": base64.b64encode(tag).decode("ascii")}
        if condition == "tampered":
            env = attacker.make_tampered(variant, env, dev._attack_rng, plaintext=plaintext, iv=iv, key_bits=key_bits)

        ev, slot = self.router.register(dev.device_id, seq)
        t_send = time.perf_counter()
        t_send_unix = time.time()
        try:
            wire_bytes = dev.channel.send_data(env)
        except Exception as exc:                                         # noqa: BLE001
            self.router.cancel(dev.device_id, seq)
            log.warning("send gagal (%s): %s", dev.device_id, exc)
            wire_bytes, ev = 0, None
        got = ev.wait(config.ACK_TIMEOUT_S) if ev is not None else False
        rec = metrics.MessageRecord(
            session_id=self.session_id, scenario=scenario, transport=self.transport, link=self.link,
            key_bits=key_bits, concurrency=concurrency, payload_bytes=payload_bytes, round=round_idx,
            device_id=dev.device_id, seq=seq, condition=condition, tamper_variant=variant,
            ciphertext_bytes=len(ct), wire_bytes=wire_bytes, encrypt_s=t_enc.elapsed_s, mac_s=t_mac.elapsed_s,
            is_synthetic_sensor=reading.synthetic, t_send_unix=t_send_unix)
        if not got:
            self.router.cancel(dev.device_id, seq)
            rec.lost = True
            return rec, None, None
        ack, t_arr = slot
        rec.rtt_s = t_arr - t_send
        rec.e2e_s = rec.encrypt_s + rec.mac_s + rec.rtt_s
        rec.accepted = bool(ack.get("accepted"))
        rec.ack_reason = str(ack.get("reason", ""))
        rec.rx_verify_s, rec.rx_decrypt_s = ack.get("vs"), ack.get("ds")
        if condition == "normal" and not rec.accepted:
            log.warning("Pesan NORMAL ditolak (%s seq=%d reason=%s) -- periksa kunci/implementasi!",
                        dev.device_id, seq, rec.ack_reason)
        if condition == "tampered" and rec.accepted:
            log.error("Pesan TAMPERED (%s) DITERIMA (%s seq=%d) -- autentikasi GAGAL mendeteksi!", variant,
                      dev.device_id, seq)
        return rec, t_arr, ack

    # ------------------------------------------------------------------ satu ronde
    def run_round(self, *, scenario: str, key_bits: int, payload_bytes: int, round_idx: int, concurrency: int):
        devs = self.devices[:concurrency]
        barrier = threading.Barrier(concurrency + 1)

        def task(d: SimDevice):
            barrier.wait()
            try:
                return self.send_one(d, scenario=scenario, key_bits=key_bits, payload_bytes=payload_bytes,
                                     round_idx=round_idx, concurrency=concurrency)
            except Exception as exc:                                     # noqa: BLE001
                log.error("task %s error: %s", d.device_id, exc)
                return None

        futs = [self.pool.submit(task, d) for d in devs]
        barrier.wait()                                                   # lepas semua thread serentak
        t0, c0, t0_unix = time.perf_counter(), metrics.cpu_time_s(), time.time()
        results = [f.result() for f in futs]
        c1 = metrics.cpu_time_s()
        good = [r for r in results if r is not None]
        recs = [r[0] for r in good]
        arrivals = [r[1] for r in good if r[1] is not None]
        t_end = max(arrivals) if arrivals else time.perf_counter()
        wall = t_end - t0
        # CPU receiver: delta antar ACK terakhir ronde ini vs ronde sebelumnya
        rx_cpu = rx_wall = rx_rss = None
        acked = [(r[1], r[2]) for r in good if r[1] is not None and r[2] is not None]
        if acked:
            t_last, ack_last = max(acked, key=lambda x: x[0])
            cpu_last = ack_last.get("rx_cpu_s")
            rx_rss = ack_last.get("rx_rss_mb")
            if cpu_last is not None:
                if self._prev_rx is not None:
                    rx_cpu, rx_wall = cpu_last - self._prev_rx[0], t_last - self._prev_rx[1]
                self._prev_rx = (cpu_last, t_last)
        n_lost = (len(devs) - len(good)) + sum(1 for r in recs if r.lost)
        rr = metrics.RoundRecord(
            session_id=self.session_id, scenario=scenario, transport=self.transport, link=self.link,
            key_bits=key_bits, concurrency=concurrency, payload_bytes=payload_bytes, round=round_idx,
            n_sent=len(devs), n_accepted=sum(1 for r in recs if r.accepted), n_lost=n_lost,
            wall_s=wall, plain_bytes_total=payload_bytes * len(devs), tx_cpu_s=c1 - c0, rx_cpu_s=rx_cpu,
            rx_wall_s=rx_wall, tx_rss_mb=0.0, rx_rss_mb=rx_rss, t_start_unix=t0_unix)
        return recs, rr


# ---------------------------------------------------------------------------
# Orkestrasi skenario
# ---------------------------------------------------------------------------
def scenario_blocks(scn: str):
    """Yield (key_bits, payload_bytes, concurrency) untuk S1..S3 (Tabel 4)."""
    if scn == "S1":
        yield config.BASELINE_KEY_BITS, config.BASELINE_PAYLOAD_BYTES, 1
    elif scn == "S2":
        for pb in config.PAYLOAD_SIZES_BYTES:
            yield config.BASELINE_KEY_BITS, pb, 1
    elif scn == "S3":
        for kb in config.KEY_BITS_LIST:
            for n in config.CONCURRENCY_LEVELS:
                yield kb, config.BASELINE_PAYLOAD_BYTES, n


def warmup_session(sess: Session, n: int):
    log.info("[%s] Pemanasan sesi: %d pesan (TIDAK dianalisis)...", sess.transport, n)
    for _ in range(n):
        sess.send_one(sess.devices[0], scenario="WARMUP", key_bits=config.BASELINE_KEY_BITS,
                      payload_bytes=config.BASELINE_PAYLOAD_BYTES, round_idx=-1, concurrency=1)


def run_perf_scenario(sess: Session, scn: str, repeats: int, warm_rounds: int, msg_log: metrics.CsvLogger,
                      run_log: metrics.CsvLogger, mon: Optional[metrics.ResourceMonitor]):
    for kb, pb, n in scenario_blocks(scn):
        if n > len(sess.devices):
            log.warning("Lewati blok concurrency=%d (hanya %d perangkat dibuat)", n, len(sess.devices))
            continue
        log.info("[%s] %s | key=%d-bit | payload=%dB | perangkat=%d | %d ronde (+%d pemanasan)",
                 sess.transport, scn, kb, pb, n, repeats, warm_rounds)
        for w in range(warm_rounds):
            sess.run_round(scenario="WARMUP", key_bits=kb, payload_bytes=pb, round_idx=-1 - w, concurrency=n)
        for r in range(repeats):
            recs, rr = sess.run_round(scenario=scn, key_bits=kb, payload_bytes=pb, round_idx=r, concurrency=n)
            rr.tx_rss_mb = mon.rss_mb() if mon else 0.0
            msg_log.log_many(recs)
            run_log.log(rr)


def run_s4(sess: Session, repeats: int, warm_rounds: int, msg_log: metrics.CsvLogger):
    dev = sess.devices[0]
    for kb in config.KEY_BITS_LIST:
        pb = config.BASELINE_PAYLOAD_BYTES
        for _ in range(warm_rounds):
            sess.send_one(dev, scenario="WARMUP", key_bits=kb, payload_bytes=pb, round_idx=-1, concurrency=1)
        plan = [("normal", "")] + [("tampered", v) for v in config.S4_TAMPER_VARIANTS]
        for cond, var in plan:
            log.info("[%s] S4 | key=%d-bit | kondisi=%s %s | %d paket", sess.transport, kb, cond, var, repeats)
            for i in range(repeats):
                rec, _, _ = sess.send_one(dev, scenario="S4", key_bits=kb, payload_bytes=pb, round_idx=i,
                                          concurrency=1, condition=cond, variant=var)
                msg_log.log(rec)


def run_stream(sess: Session, args):
    """Simulasi STREAMING data suhu (cek pipeline sensor -> enkripsi -> transmisi -> verifikasi)."""
    dev = sess.devices[0]
    log_ = metrics.CsvLogger(config.metrics_csv_path("device", "STREAM"), metrics.MessageRecord)
    log.info("[%s] STREAMING %ss, interval %.2fs, key=%d-bit, payload=%dB (data sensor: SINTETIS)",
             sess.transport, args.duration, args.interval, args.stream_key_bits, args.stream_payload)
    end = time.monotonic() + args.duration
    nxt = time.monotonic()
    while time.monotonic() < end:
        rec, _, _ = sess.send_one(dev, scenario="STREAM", key_bits=args.stream_key_bits,
                                  payload_bytes=args.stream_payload, round_idx=dev.seq, concurrency=1)
        log_.log(rec)
        status = "LOST" if rec.lost else ("DITERIMA" if rec.accepted else f"DITOLAK({rec.ack_reason})")
        rtt = f"{rec.rtt_s * 1000:.2f} ms" if rec.rtt_s is not None else "-"
        print(f"  #{rec.seq:<4d} [{'SINTETIS' if rec.is_synthetic_sensor else 'SENSOR-FISIK'}] "
              f"key={rec.key_bits}b ct={rec.ciphertext_bytes}B enc={rec.encrypt_s * 1e3:.2f}ms "
              f"mac={rec.mac_s * 1e3:.2f}ms rtt={rtt} -> {status}", flush=True)
        nxt += args.interval
        time.sleep(max(0.0, nxt - time.monotonic()))


def write_metadata(session_id: str, args, transports, links):
    import os
    meta = {"session_id": session_id, "started_at_unix": time.time(),
            "python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine(),
            "processor": platform.processor(), "cpu_count": os.cpu_count(),
            "transports": list(transports), "links": links,
            "algorithm": "PRESENT-CBC(PKCS7)+PRESENT-CBC-MAC(len-prefix), enc/mac key terpisah",
            "key_bits": list(config.KEY_BITS_LIST), "repeats": args.repeats,
            "warmup_session_msgs": args.warmup, "warmup_rounds_per_block": config.WARMUP_ROUNDS_PER_BLOCK,
            "payload_sizes": list(config.PAYLOAD_SIZES_BYTES), "concurrency_levels": list(config.CONCURRENCY_LEVELS),
            "mqtt_qos": config.MQTT_QOS, "ack_timeout_s": config.ACK_TIMEOUT_S,
            "resource_sampling_interval_s": config.RESOURCE_SAMPLING_INTERVAL_S,
            "sensor": "SINTETIS (BME280 belum terpasang)", "scenario_arg": args.scenario}
    for mod in ("paho.mqtt", "serial", "psutil"):
        try:
            m = __import__(mod, fromlist=["x"])
            meta.setdefault("libs", {})[mod] = getattr(m, "__version__", getattr(m, "VERSION", "?"))
        except Exception:                                                # noqa: BLE001
            meta.setdefault("libs", {})[mod] = "tidak terpasang"
    path = config.metrics_csv_path("run", "metadata").replace(".csv", ".json")
    try:
        all_meta = json.load(open(path))
    except (OSError, ValueError):
        all_meta = []
    all_meta.append(meta)
    json.dump(all_meta, open(path, "w"), indent=2, default=str)


def build_arg_parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--transport", choices=["uart", "mqtt", "both"], default="both")
    p.add_argument("--uart-port", default=None, help="port serial nyata (COM5, /dev/ttyACM0) atau URL pyserial")
    p.add_argument("--baud", type=int, default=config.UART_BAUDRATE)
    p.add_argument("--tcp-port", type=int, default=None, help="pengganti UART (TCP loopback) -- harus sama dgn receiver")
    p.add_argument("--mqtt-host", default=config.MQTT_HOST)
    p.add_argument("--mqtt-port", type=int, default=config.MQTT_PORT)
    p.add_argument("--scenario", choices=["S1", "S2", "S3", "S4", "all"], default="all")
    p.add_argument("--repeats", type=int, default=config.REPEATS)
    p.add_argument("--warmup", type=int, default=config.WARMUP_SESSION_MSGS)
    p.add_argument("--wire-tap", default=None, help="tulis paket-di-kabel ke berkas ini (untuk verify_capture)")
    p.add_argument("--stream", action="store_true", help="mode streaming data suhu (bukan S1-S4)")
    p.add_argument("--duration", type=float, default=30.0)
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--stream-key-bits", type=int, choices=[80, 128], default=80)
    p.add_argument("--stream-payload", type=int, default=64)
    return p


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    transports = ["uart", "mqtt"] if args.transport == "both" else [args.transport]
    if "uart" in transports and not (args.uart_port or args.tcp_port):
        sys.exit("Jalur UART butuh --uart-port (serial nyata) atau --tcp-port (pengganti UART tanpa driver).")
    scns = ["S1", "S2", "S3", "S4"] if args.scenario == "all" else [args.scenario]
    session_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
    max_n = max(config.CONCURRENCY_LEVELS) if ("S3" in scns and not args.stream) else 1

    mon = metrics.ResourceMonitor("sender", config.metrics_csv_path("resources", "sender"),
                                  config.RESOURCE_SAMPLING_INTERVAL_S)
    mon.start()
    links = {}
    try:
        for tr in transports:
            sess = Session(tr, max_n, args, session_id)
            links[tr] = sess.link
            sess.open()
            try:
                warmup_session(sess, args.warmup)
                if args.stream:
                    run_stream(sess, args)
                    continue
                for scn in scns:
                    if scn == "S4":
                        run_s4(sess, args.repeats, config.WARMUP_ROUNDS_PER_BLOCK,
                               metrics.CsvLogger(config.metrics_csv_path("device", "S4"), metrics.MessageRecord))
                    else:
                        run_perf_scenario(sess, scn, args.repeats, config.WARMUP_ROUNDS_PER_BLOCK,
                                          metrics.CsvLogger(config.metrics_csv_path("device", scn), metrics.MessageRecord),
                                          metrics.CsvLogger(config.metrics_csv_path("runs", scn), metrics.RoundRecord), mon)
            finally:
                sess.close()
        write_metadata(session_id, args, transports, links)
        log.info("Selesai. Sesi=%s. Jalankan: python3 analyze.py", session_id)
    finally:
        mon.stop()


if __name__ == "__main__":
    main()
