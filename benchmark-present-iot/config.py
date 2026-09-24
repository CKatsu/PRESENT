"""
config.py
=========
Konfigurasi terpusat seluruh modul (receiver_server, device_sim, attacker,
metrics, analyze). Semua parameter eksperimen ada di sini agar mudah dicatat
untuk reproducibility (lihat README "Reproducibility").

Nilai default = REKOMENDASI/keputusan desain, BUKAN hasil eksperimen.
Ubah -> catat perubahan di laporan.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# PRESENT_OUT_DIR (opsional) memindahkan data/, results/ dan summary.json ke folder lain --
# dipakai tests/ agar uji-coba tidak mencampuri data eksperimen asli.
OUT_DIR = os.environ.get("PRESENT_OUT_DIR", BASE_DIR)
DATA_DIR = os.path.join(OUT_DIR, "data")
RESULTS_DIR = os.path.join(OUT_DIR, "results")
CHARTS_DIR = os.path.join(RESULTS_DIR, "charts")
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")
DB_PATH = os.path.join(DATA_DIR, "log.sqlite")
SUMMARY_JSON_PATH = os.path.join(OUT_DIR if OUT_DIR != BASE_DIR else DASHBOARD_DIR, "summary.json")
for _d in (DATA_DIR, RESULTS_DIR, CHARTS_DIR):
    os.makedirs(_d, exist_ok=True)

# ---------------------------------------------------------------------------
# Kunci (fase 3.1: "dimuat dari berkas konfigurasi"). KUNCI UJI AKADEMIK, bukan
# rahasia produksi -- hanya perlu konsisten antar sesi & sama dengan firmware
# (esp32-firmware/include/config.h). Kunci ENC dan MAC dipisah (key separation);
# tiap varian panjang kunci memakai pasangan sendiri. Boleh dioverride lewat
# environment variable (hex) agar tidak ikut ter-commit bila ingin diganti.
# ---------------------------------------------------------------------------
def _hex_env(name: str, default_hex: str, nbytes: int) -> bytes:
    raw = bytes.fromhex(os.environ.get(name, default_hex))
    if len(raw) != nbytes:
        raise ValueError(f"{name} harus {nbytes} byte ({nbytes*2} karakter hex)")
    return raw


KEYS = {
    80: {
        "enc": _hex_env("PRESENT_ENC_KEY_80", "0f1e2d3c4b5a69788796", 10),
        "mac": _hex_env("PRESENT_MAC_KEY_80", "a1b2c3d4e5f60718293a", 10),
    },
    128: {
        "enc": _hex_env("PRESENT_ENC_KEY_128", "00112233445566778899aabbccddeeff", 16),
        "mac": _hex_env("PRESENT_MAC_KEY_128", "ffeeddccbbaa99887766554433221100", 16),
    },
}

# "Kunci salah" untuk varian tampered S4: semua byte kunci di-XOR 0x5A.
WRONG_KEY_XOR = 0x5A

# IV awal (fase 3.1). Dipakai sebagai SEED generator IV per-pesan supaya urutan IV
# dapat direproduksi; IV tetap DIBUAT BARU tiap pesan (CBC dengan IV tetap tidak
# aman) dan dikirim bersama pesan. Firmware memakai esp_random().
IV_SEED = os.environ.get("PRESENT_IV_SEED", "PRESENT-IV-SEED-2026")

# ---------------------------------------------------------------------------
# Protokol / jalur komunikasi
# ---------------------------------------------------------------------------
PROTOCOL_PREFIX = "PRS1:"       # baris UART: "PRS1:{json}\n"  (baris lain = log, diabaikan)

UART_PORT = os.environ.get("PRESENT_UART_PORT", "/dev/ttyACM0")   # Windows: "COM5"
UART_BAUDRATE = int(os.environ.get("PRESENT_UART_BAUD", "115200"))
UART_TIMEOUT_S = 2.0
TCP_HOST = "127.0.0.1"           # mode "tcp" = pengganti UART (tanpa driver serial virtual)
TCP_PORT = int(os.environ.get("PRESENT_TCP_PORT", "9999"))

MQTT_HOST = os.environ.get("PRESENT_MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.environ.get("PRESENT_MQTT_PORT", "1883"))
MQTT_QOS = int(os.environ.get("PRESENT_MQTT_QOS", "1"))
MQTT_TOPIC_DATA = "present/{device_id}/data"       # device -> receiver
MQTT_TOPIC_ACK = "present/{device_id}/ack"         # receiver -> device
MQTT_SUB_ALL_DATA = "present/+/data"
MQTT_KEEPALIVE_S = 30

ACK_TIMEOUT_S = 5.0              # pesan tanpa ACK dalam batas ini dicatat "lost"

# ---------------------------------------------------------------------------
# Parameter eksperimen (Tabel 3 & 4 kerangka)
# ---------------------------------------------------------------------------
TRANSPORTS = ("uart", "mqtt")
KEY_BITS_LIST = (80, 128)
PAYLOAD_SIZES_BYTES = (64, 256, 1024)      # S2
BASELINE_PAYLOAD_BYTES = 64                # S1, S3, S4
BASELINE_KEY_BITS = 80                     # S1, S2 (S3 memvariasikan 80/128)
CONCURRENCY_LEVELS = (1, 10, 50)           # S3

REPEATS = int(os.environ.get("PRESENT_REPEATS", "31"))
# Definisi 1 pengulangan (repetition) = 1 "ronde": tiap perangkat konkuren mengirim
# TEPAT SATU pesan serentak (barrier), lalu semua ACK ditunggu. Unit statistik
# (mean/SD/CI, n=31) = nilai ringkasan per ronde. Untuk 1 perangkat: 1 pesan/ronde.
WARMUP_SESSION_MSGS = 10                   # per jalur, di awal sesi (fase 3.2)
WARMUP_ROUNDS_PER_BLOCK = 2                # ronde pemanasan (tidak dicatat) sebelum tiap kombinasi
S4_TAMPER_VARIANTS = ("flip_ciphertext_bit", "random_tag", "modify_iv", "wrong_key")

RESOURCE_SAMPLING_INTERVAL_S = 1.0         # fase 3.1: pencuplikan CPU/RAM tiap 1 detik

# ---------------------------------------------------------------------------
# Payload sintetis (BME280 belum terpasang). ASUMSI ruangan tropis, bukan kalibrasi.
# ---------------------------------------------------------------------------
SYN_TEMP_BASE_C, SYN_TEMP_JITTER_C = 28.0, 1.5
SYN_HUM_BASE_PCT, SYN_HUM_JITTER_PCT = 65.0, 8.0
SYN_PRES_BASE_HPA, SYN_PRES_JITTER_HPA = 1009.0, 2.0
SENSOR_SEED = int(os.environ.get("PRESENT_SENSOR_SEED", "20260924"))


def metrics_csv_path(role: str, name: str) -> str:
    """role: 'device' | 'server' | 'runs' | 'resources_*'. Dipisah per proses agar
    dua proses tidak menulis file yang sama bersamaan."""
    return os.path.join(RESULTS_DIR, f"{role}_{name}.csv")
