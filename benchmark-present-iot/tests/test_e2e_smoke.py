"""
tests/test_e2e_smoke.py
========================
Uji end-to-end otomatis: menjalankan receiver_server.py dan device_sim.py sebagai
DUA PROSES terpisah lalu memeriksa hasilnya. Output ke folder sementara
(PRESENT_OUT_DIR) -- tidak menyentuh data/ dan results/ asli.

  python3 tests/test_e2e_smoke.py tcp      # jalur nyata stdlib: TCP loopback (pengganti UART)
  python3 tests/test_e2e_smoke.py fakes    # UART via pyserial-PALSU + MQTT via paho/broker-PALSU
                                            # (menguji LOGIKA uart_channel/mqtt_channel/konkurensi;
                                            #  BUKAN pyserial/Mosquitto asli)
  python3 tests/test_e2e_smoke.py real     # pyserial & paho-mqtt ASLI + Mosquitto di localhost:1883,
                                            # UART lewat --uart-port dari env PRESENT_TEST_UART
                                            # (mis. socket://127.0.0.1:7000 / loop / COM virtual). Jalankan
                                            # di komputer Anda.

Kriteria lulus: tidak ada pesan lost; semua pesan normal diterima; semua tampered
ditolak (DR=100%, FRR=0%); jumlah baris CSV sesuai; DB terisi.
"""
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPEATS = int(os.environ.get("SMOKE_REPEATS", "4"))


def main(mode: str) -> int:
    out = tempfile.mkdtemp(prefix="present_smoke_")
    env = dict(os.environ, PRESENT_OUT_DIR=out, PYTHONUNBUFFERED="1")
    procs, rx_args, dev_args = [], [], []
    if mode == "fakes":
        env["PYTHONPATH"] = os.path.join(ROOT, "tests", "fakes") + os.pathsep + env.get("PYTHONPATH", "")
        broker = subprocess.Popen([sys.executable, os.path.join(ROOT, "tests", "fakes", "fake_mqtt_broker.py"), "18830"],
                                  env=env, stdout=subprocess.DEVNULL)
        procs.append(broker)
        rx_args = ["--uart-port", "fake://smoke#a", "--mqtt", "--mqtt-port", "18830"]
        dev_args = ["--transport", "both", "--uart-port", "fake://smoke#b", "--mqtt-port", "18830"]
        time.sleep(1.0)
    elif mode == "tcp":
        rx_args = ["--tcp-port", "19999"]
        dev_args = ["--transport", "uart", "--tcp-port", "19999"]
    elif mode == "real":
        uart = os.environ.get("PRESENT_TEST_UART")
        rx_uart = os.environ.get("PRESENT_TEST_UART_RX")
        if not uart or not rx_uart:
            sys.exit("Set PRESENT_TEST_UART (sisi device) dan PRESENT_TEST_UART_RX (sisi receiver), mis. dua ujung "
                     "pasangan serial virtual (com0com/socat) -- dan pastikan Mosquitto jalan di localhost:1883.")
        rx_args = ["--uart-port", rx_uart, "--mqtt"]
        dev_args = ["--transport", "both", "--uart-port", uart]
    else:
        sys.exit("mode: tcp | fakes | real")
    try:
        rx = subprocess.Popen([sys.executable, os.path.join(ROOT, "receiver_server.py")] + rx_args, env=env,
                              stdout=open(os.path.join(out, "rx.log"), "w"), stderr=subprocess.STDOUT)
        procs.append(rx)
        time.sleep(2.0)
        t0 = time.time()
        r = subprocess.run([sys.executable, os.path.join(ROOT, "device_sim.py")] + dev_args +
                           ["--scenario", "all", "--repeats", str(REPEATS)], env=env, capture_output=True, text=True, timeout=900)
        print(f"device_sim selesai dalam {time.time() - t0:.1f}s, exit={r.returncode}")
        if r.returncode != 0:
            print(r.stdout[-2000:], r.stderr[-3000:])
            return 1
        time.sleep(1.5)                                   # beri waktu AsyncWriter menguras antrean
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill()

    import pandas as pd
    import sqlite3
    ok = True
    def check(cond, msg):
        nonlocal ok
        print(("  PASS  " if cond else "  FAIL  ") + msg)
        ok &= bool(cond)

    res = os.path.join(out, "results")
    transports = ["uart", "mqtt"] if mode != "tcp" else ["uart"]
    s1, s2, s3, s4 = (pd.read_csv(os.path.join(res, f"device_S{i}.csv")) for i in (1, 2, 3, 4))
    for d in (s1, s2, s3, s4):
        check(d.lost.sum() == 0, f"tidak ada pesan lost ({d.scenario.iloc[0]})")
    nt = len(transports)
    check(len(s1) == REPEATS * nt, f"S1 {len(s1)} baris == {REPEATS}x{nt}")
    check(len(s2) == REPEATS * 3 * nt, f"S2 {len(s2)} baris")
    exp_s3 = REPEATS * 2 * (1 + 10 + 50) * nt
    check(len(s3) == exp_s3, f"S3 {len(s3)} baris == {exp_s3}")
    check(s3.accepted.all(), "S3 semua diterima")
    normal, tam = s4[s4.condition == "normal"], s4[s4.condition == "tampered"]
    check(normal.accepted.all(), f"S4 normal {len(normal)}/{len(normal)} diterima (FRR=0%)")
    check((~tam.accepted.astype(bool)).all() and len(tam) == REPEATS * 4 * 2 * nt,
          f"S4 tampered {len(tam)}/{len(tam)} ditolak (DR=100%)")
    check(set(s4.link) == set({"uart": "serial" if mode != "tcp" else "tcp-loopback", "mqtt": "mqtt-broker"}[t] for t in transports)
          or mode == "tcp", "kolom link terisi sesuai jalur")
    srv = pd.read_csv(os.path.join(res, "server_all.csv"))
    check(len(srv) == len(s1) + len(s2) + len(s3) + len(s4), f"CSV server {len(srv)} baris == total pesan sisi device")
    check(srv[srv.condition_label == "normal"].accepted.all(), "server: semua label normal diterima")
    check((~srv[srv.condition_label == "tampered"].accepted).all(), "server: semua tampered ditolak")
    runs3 = pd.read_csv(os.path.join(res, "runs_S3.csv"))
    check(runs3.rx_cpu_s.notna().mean() > 0.9, "runs_S3: rx_cpu_s terisi")
    conn = sqlite3.connect(os.path.join(out, "data", "log.sqlite"))
    nvalid = conn.execute("select count(*) from valid_readings").fetchone()[0]
    nsyn = conn.execute("select count(*) from valid_readings where is_synthetic_sensor=1").fetchone()[0]
    check(nvalid == len(srv[srv.accepted]) and nvalid == nsyn, f"SQLite valid_readings={nvalid} semuanya bertanda sintetis")
    print("Folder keluaran uji:", out)
    print("SMOKE TEST", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "tcp"))
