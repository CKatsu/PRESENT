# Benchmarking PRESENT (80/128-bit) pada IoT: UART & MQTT

Implementasi dokumen **"Rancangan Simulasi Benchmarking Algoritma Kriptografi PRESENT dengan Beban Kerja pada Perangkat IoT"** (`Kerangka_Benchmark_PRESENT_IoT.docx`, sumber kebenaran desain). Proyek SPECK hanya dipakai sebagai referensi *gaya kerja* (KAT dulu, CSV mentah dulu, warmup terpisah, tanpa data karangan, dashboard non-real-time), bukan parameter/arsitektur.

## Struktur (mengikuti Tabel 1 kerangka)

```
present-iot-benchmark/
├── benchmark-present-iot/
│   ├── receiver_server.py   # penerima UART & MQTT: verifikasi tag -> dekripsi -> SQLite/CSV
│   ├── device_sim.py        # simulator perangkat: S1-S4, 1/10/50 perangkat, mode --stream
│   ├── crypto_utils.py      # PRESENT-80/128 + CBC(PKCS#7) + PRESENT-CBC-MAC (+ KAT saat import)
│   ├── uart_channel.py      # pyserial (COM/tty/URL) dan TCP-loopback (pengganti UART tanpa driver)
│   ├── mqtt_channel.py      # paho-mqtt -> broker Mosquitto (AKTIF, bukan stub)
│   ├── attacker.py          # 4 varian tampered S4
│   ├── metrics.py           # RTT, waktu kripto, CPU/RAM (psutil), skema CSV
│   ├── analyze.py           # mean/SD/CI95, DR/FRR, grafik, dashboard/summary.json
│   ├── dashboard/index.html # non-real-time (memuat summary.json sekali / saat tombol ditekan)
│   ├── data/log.sqlite      # (dibangkitkan) tabel valid_readings + verification_log
│   ├── results/             # (dibangkitkan) CSV mentah, statistik, grafik, run_metadata.json
│   ├── config.py, payload_format.py, channel_base.py      # pendukung (di luar Tabel 1)
│   ├── tools/verify_capture.py, tools/mosquitto_present.conf
│   └── tests/               # KAT, cross-check C, uji end-to-end, fake pyserial/paho
└── esp32-firmware/          # PlatformIO (ESP32-S3 N16R8): streaming PRESENT, UART atau MQTT
```

## STATUS VERIFIKASI: apa yang sudah teruji, apa yang BELUM

Dikerjakan di sandbox cloud yang **tidak bisa memasang pyserial, paho-mqtt, Mosquitto, maupun PlatformIO** (egress diblokir). Jadi:

| Komponen | Status |
|---|---|
| PRESENT-80 vs KAT resmi (4 vektor, Bogdanov et al. 2007) di Python **dan** C | LULUS (nilai sama dengan dokumentasi SageMath) |
| PRESENT-128 | Python == C == implementasi referensi bit-demi-bit. **Paper asli tidak memuat vektor 128-bit**; 3 dari 4 vektor di `tests/test_present_kat.py` cocok dengan nilai sekunder yang saya ingat, tapi **belum saya verifikasi ke sumber primer (mis. ISO/IEC 29192-2)**. Verifikasi sendiri sebelum menyebutnya "KAT resmi". Vektor `key=0,pt=ff..ff` hanya dari implementasi ini |
| Cross-check C vs Python (308 vektor CBC+CBC-MAC, kunci 80/128) | LULUS |
| End-to-end S1-S4, 2 proses terpisah, jalur **TCP loopback** (stdlib nyata) | LULUS |
| Jalur **UART (pyserial)** dan **MQTT (paho)** | Logika teruji **hanya dengan pyserial/paho/broker PALSU** (`tests/fakes/`). **pyserial asli, paho asli, dan Mosquitto asli belum pernah dijalankan**. Wajib Anda uji: `tests/test_e2e_smoke.py real` |
| Firmware: logika aplikasi (`main.cpp` asli + stub Arduino) -> receiver Python | LULUS untuk key 80/128, payload 64/256/1024, demo tampered |
| Firmware: kompilasi PlatformIO, upload, I2C BME280, USB-serial, WiFi/MQTT di hardware | **BELUM** (tidak bisa diunduh toolchain-nya). Jalankan `pio run` dulu |
| `verify_capture.py` | Teruji dengan pcap/pcapng **sintetis** + kontrol positif. Capture Wireshark asli belum |
| Dashboard | Dirender di Chromium headless (tanpa error JS) dengan data uji |

**Tidak ada angka hasil eksperimen di repo ini.** Semua angka yang saya lihat berasal dari uji fungsional di sandbox (transport palsu/loopback), tidak relevan untuk skripsi, dan sudah dihapus. Dashboard tanpa data menampilkan `[HASIL PENGUJIAN]`.

## Keputusan desain (kerangka tidak menetapkan, atau ada hal yang perlu Anda putuskan)

1. **Kunci ENC dan MAC dipisah**, tiap varian panjang kunci punya pasangan sendiri (`config.py` <-> `esp32-firmware/include/config.h`, harus identik). Kunci = konstanta uji, bukan rahasia.
2. **CBC-MAC dengan awalan panjang + encrypt-then-MAC** atas `IV || ciphertext`. CBC-MAC polos tidak aman untuk pesan berbeda panjang (S2 memakai 64/256/1024 B). Ada uji khusus. **Tag = 64 bit** (satu blok PRESENT): batas bawaan desain, catat sebagai keterbatasan keamanan (bukan kelemahan yang bisa dihilangkan tanpa mengganti primitif).
3. **IV**: kerangka menyebut "IV awal dari berkas konfigurasi". CBC dengan IV tetap tidak aman, jadi `IV_SEED` di config hanya seed generator IV per-pesan (urutan reproducible), IV baru tiap pesan dan dikirim bersama paket. Firmware memakai `esp_random()`. Bila pembimbing menghendaki IV tetap, itu perubahan yang harus dicatat sebagai deviasi keamanan.
4. **Padding PKCS#7** (selalu +1..8 byte), jadi ciphertext 64 B -> 72 B (overhead 12,5%), 256 -> 264, 1024 -> 1032. Overhead tercatat di `summary_stats.csv`.
5. **Payload = JSON ringkas + padding spasi** sampai tepat 64/256/1024 B (ukuran = plaintext sebelum padding kripto).
6. **Deviasi kanal sensor**: kerangka menyebut suhu/kelembaban/**cahaya**; GY-BME280 tidak punya sensor cahaya, jadi kanal ketiga = **tekanan (hPa)**. Ubah jika pembimbing menginginkan lain.
7. **Definisi 1 pengulangan = 1 ronde**: tiap perangkat konkuren mengirim tepat 1 pesan serentak (barrier); 31 ronde per kombinasi; unit statistik (mean/SD/CI, n=31) = ringkasan per ronde. Warmup: 10 pesan per jalur di awal sesi + 2 ronde per blok, tidak dicatat (receiver memverifikasi tapi tidak menyimpan `scenario=WARMUP`).
8. **Parameter yang tidak ditetapkan Tabel 4**: S2 memakai kunci 80-bit, 1 perangkat; S3 memakai payload 64 B; S4 dijalankan untuk **kedua** panjang kunci (payload 64 B, 1 perangkat), 31 paket normal + 31 per varian tampered untuk tiap (jalur x kunci). Ubah di `config.py` bila perlu. S1, S2(64B), dan S3(80,1) secara konsep sama tetapi dijalankan sebagai run independen.
9. **Kelayakan 50 perangkat konkuren: layak, dengan tafsir yang harus jujur.** 50 "perangkat" = 50 thread dalam satu proses Python (GIL): satu uplink UART dimultipleks (frame antre di satu kabel), atau 50 koneksi MQTT ke broker. Bukan 50 MCU dan bukan 50 core paralel. Konsekuensi: (a) RTT pada N=10/50 memuat antrean sender+receiver+link, bukan hanya PRESENT; (b) **waktu kripto murni hanya dilaporkan untuk 1 perangkat** (pada N>1 ikut menunggu GIL); (c) receiver = satu pemroses (model gateway tunggal). Di sandbox seluruh 31 pengulangan S1-S4 selesai ~13 detik pada transport palsu; pada UART 115200 baud asli akan lebih lama (dominan waktu serial).
10. **"UART" tanpa hardware**: `--tcp-port` = loopback lokal, ditandai `link=tcp-loopback` di setiap baris CSV. Jangan dilaporkan sebagai pengukuran UART hardware. Data UART sungguhan hanya dari ESP32-S3 (`link=serial`). Catatan: USB-CDC ESP32-S3 mengabaikan baud rate.
11. **CPU/RAM** = proses sender/receiver di komputer **host** (sesuai batasan kerangka #1). Sampling psutil 1 detik (fase 3.1) tersimpan mentah di `results/resources_*.csv`; per ronde juga dicatat delta waktu-CPU proses. Resolusi jam CPU Windows ~15,6 ms, jadi CPU% per ronde pendek kasar; `analyze.py` memakai **CPU% per blok** (jumlah delta / jumlah waktu) sebagai angka utama. RAM = RSS.
12. **Latensi**: `rtt_s` = kirim -> ACK aplikasi (transport + verifikasi/dekripsi receiver; penulisan DB sengaja di luar jalur ACK). `e2e_s` = enkripsi + MAC + RTT. Waktu enkripsi, MAC, verifikasi, dekripsi dicatat **terpisah**.
13. **Throughput**: agregat per ronde = byte plaintext / waktu-dinding ronde. Angka pada blok sangat cepat (mis. 1 pesan ~1 ms) berfluktuasi besar; lihat SD/CI.
14. **MQTT QoS 1** (`config.MQTT_QOS`), receiver mendeduplikasi (`run_id`,`seq`). Broker Mosquitto lokal tanpa TLS/autentikasi (sengaja, agar bisa di-capture).
15. **Firmware = mode streaming** (bukan otomasi S1-S4, sama seperti SPECK). Firmware mengukur waktu kripto ESP32 (`enc_us`, esp_timer) dan dikirim ke receiver -> kolom `device_enc_us` di `server_all.csv`. Ini satu-satunya angka waktu kripto yang benar-benar dari mikrokontroler.

## Setup PC

Python 3.10+. **Windows (PowerShell)**:

```powershell
cd present-iot-benchmark\benchmark-present-iot
python3 -m venv .venv
.venv\Scripts\Activate.ps1         # bila ditolak execution policy, lewati venv
python3 -m pip install -r requirements.txt
```

Linux/macOS: `python3 -m venv .venv && source .venv/bin/activate && python3 -m pip install -r requirements.txt`.

### Mosquitto (Windows)

1. Pasang Mosquitto dari mosquitto.org/download (installer Windows), tambahkan folder instalasinya ke `PATH`.
2. Jalankan dengan konfigurasi uji (Mosquitto 2.x menolak koneksi non-lokal/anonim tanpa konfigurasi; verifikasi perilaku pada versi Anda):
   `mosquitto -c tools\mosquitto_present.conf -v`
3. Uji cepat di terminal lain: `mosquitto_sub -t "test/#"` dan `mosquitto_pub -t test/a -m hi`.
4. Untuk ESP32 (env `esp32s3-mqtt`): isi `include/secrets.h` dengan **IP LAN komputer Anda** (bukan localhost) dan izinkan port 1883 di Windows Firewall.

## WAJIB sebelum ambil data

```bash
python3 tests/run_all_tests.py             # KAT + cross-check C + e2e (TCP & fake) -> harus LULUS semua
python3 tests/test_e2e_smoke.py real       # pyserial/paho/Mosquitto ASLI (butuh env PRESENT_TEST_UART & _RX, lihat docstring)
```

Jika KAT gagal, **jangan** benchmark. `crypto_utils.py` juga meng-assert KAT-80 saat di-import.

## Menjalankan

Urutan: **receiver dulu**, baru `device_sim`. Tiga terminal (Mosquitto, receiver, device_sim).

```bash
# Terminal 1: broker
mosquitto -c tools/mosquitto_present.conf -v

# Terminal 2: receiver (dua jalur aktif sekaligus)
python3 receiver_server.py --tcp-port 9999 --mqtt            # UART-pengganti + MQTT
python3 receiver_server.py --uart-port COM5 --mqtt           # ESP32-S3 asli (UART) + MQTT

# Terminal 3: seluruh skenario S1-S4, 31 ronde per kombinasi
python3 device_sim.py --scenario all --transport both --tcp-port 9999
python3 device_sim.py --scenario S3 --transport mqtt          # satu skenario / satu jalur

# Simulasi STREAMING data suhu (cek pipeline sensor->enkripsi->kirim->verifikasi)
python3 device_sim.py --stream --transport mqtt --duration 60 --interval 1 --stream-key-bits 128

# Analisis + dashboard (non-real-time)
python3 analyze.py                              # jalankan ulang setiap selesai sesi baru
cd dashboard; python3 -m http.server 8000       # buka http://localhost:8000, klik "Muat Ulang Data"
```

Data mentah per-pesan: `results/device_S*.csv` (sender), `results/server_all.csv` (receiver); per-ronde: `results/runs_S*.csv`; linimasa CPU/RAM: `results/resources_*.csv`; metadata reproducibility: `results/run_metadata.json`. `analyze.py` memakai **sesi terbaru** per (skenario, jalur) agar 31 pengulangan tidak tercampur (`--session all` untuk menggabungkan).

Data streaming ESP32-S3 asli: jalankan `receiver_server.py --uart-port COMx` saja; paket bertanda `scenario=STREAM`, tersimpan di SQLite dan tampil di bagian sensor dashboard dengan badge **SINTETIS/FISIK**.

## Verifikasi ciphertext di jaringan (Wireshark + Npcap)

1. Windows: pasang Wireshark + Npcap (opsi *loopback support*). Capture pada **"Adapter for loopback traffic capture"**, filter tampilan `tcp.port == 1883` (MQTT) atau `tcp.port == 9999` (TCP pengganti UART).
2. Jalankan `device_sim.py` (mis. `--scenario S1`), hentikan capture, simpan `.pcapng`.
3. `python3 tools/verify_capture.py --pcap capture.pcapng` -> memeriksa: ada paket terenkripsi, tidak ada pola plaintext sensor, tidak ada blok ciphertext berulang (ECB-like), entropi ~8 bit/byte, plus **kontrol positif** (paket plaintext buatan harus terdeteksi bocor). Untuk lampiran skripsi: tangkapan layar Wireshark "Follow TCP Stream" + keluaran skrip.
4. Jalur serial tidak bisa di-capture Wireshark biasa: pakai `device_sim.py --wire-tap results/wire_uart.log` lalu `verify_capture.py --raw results/wire_uart.log`. **Catatan jujur**: itu salinan paket yang ditulis sender (sebelum driver serial), bukan sniffing fisik kabel. Untuk bukti fisik gunakan sniffer serial/logic analyzer.

Header/topik MQTT dan field envelope (device_id, seq, IV, tag) terlihat sebagai teks: itu metadata. Yang harus tidak terbaca adalah isi sensor di dalam `ct`.

## Firmware ESP32-S3

```bash
cd esp32-firmware
pio run -e esp32s3-uart                 # LANGKAH 1: compile saja (toolchain belum teruji oleh saya)
pio run -e esp32s3-uart -t upload
pio device monitor                       # baris '#' = log; 'PRS1:' = paket
```

- Board generik `esp32-s3-devkitc-1` dengan override 16 MB flash + PSRAM OPI (N16R8). Sesuaikan bila board berbeda.
- Panjang kunci: `-DPRESENT_KEY_BITS=80|128` (`platformio.ini`); payload: `PAYLOAD_TARGET_SIZE_BYTES` di `include/config.h`.
- **Pin I2C BME280** (`BME280_SDA_PIN/SCL_PIN`, default GPIO8/9) adalah asumsi; cocokkan dengan board Anda.
- Saat boot firmware menjalankan **KAT PRESENT-80 dan berhenti total bila gagal**.
- BME280 terdeteksi -> otomatis pembacaan fisik (`"s":0`, badge FISIK); tidak terdeteksi -> sintetis (`"s":1`). Tidak ada perubahan struktur data/kode.
- Implementasi C = referensi (S-box per nibble, pLayer per bit), tanpa tabel dan tanpa alokasi dinamis. Implementasi Python memakai tabel S-box+pLayer gabungan sebagai **optimasi implementasi** (hasil identik, diuji). Waktu kripto Python **bukan** waktu ESP32.
- Varian MQTT firmware memakai PubSubClient (QoS 0 dari sisi publish). Belum diuji di hardware.

## Reproducibility

| Parameter | Nilai |
|---|---|
| Algoritma | PRESENT-80 / PRESENT-128 (Bogdanov et al., CHES 2007), 31 round + whitening, blok 64 bit |
| Mode & MAC | CBC + PKCS#7; PRESENT-CBC-MAC (awalan panjang, tag 8 B), encrypt-then-MAC, kunci ENC/MAC terpisah |
| Payload S2 | 64, 256, 1024 B (JSON + spasi); S1/S3/S4: 64 B |
| Konkurensi (S3) | 1, 10, 50 (thread, satu proses) |
| Pengulangan | 31 ronde per kombinasi; warmup 10 pesan/jalur + 2 ronde/blok (dibuang) |
| Waktu | `time.perf_counter()` (Python); `esp_timer_get_time()` (firmware, mikrodetik) |
| CPU/RAM | psutil (1 s) + delta `time.process_time()`; proses host, bukan MCU |
| Statistik | mean, SD sampel (ddof=1), CI95 = mean ± t(0,975; n-1)·SD/√n; DR/FRR dengan CI Clopper-Pearson |
| MQTT | paho-mqtt, Mosquitto lokal, QoS 1 |
| Dicatat otomatis | `results/run_metadata.json`: Python, OS, CPU, versi pustaka, parameter sesi |

Catat juga: versi Mosquitto, model/klok ESP32-S3, versi PlatformIO/framework, dan kondisi komputer (tanpa aplikasi berat lain).

## Keterbatasan

1. CPU/RAM dan waktu Python adalah proses host, bukan mikrokontroler; hanya `enc_us` firmware yang berasal dari MCU.
2. Latensi = kripto + jalur (UART/MQTT lokal) + pemrosesan receiver, bukan latensi nirkabel skala luas.
3. Data sensor **sintetis** (BME280 belum terpasang), berlabel di tiap rekaman.
4. Konkurensi lewat thread + GIL, bukan perangkat paralel; waktu kripto murni hanya untuk 1 perangkat.
5. Uji keamanan terbatas pada integritas/autentikasi (CBC-MAC), bukan kriptanalisis PRESENT dan bukan serangan lapisan jaringan. Tag 64 bit; blok 64 bit membatasi volume data per kunci (batas *birthday* ~2^32 blok, jauh di atas skala benchmark ini).
6. Kunci uji tertanam di repo (akademik, bukan produksi).
7. "UART" via TCP-loopback bukan pengukuran UART hardware.
8. Vektor uji PRESENT-128 belum diverifikasi ke sumber primer (lihat tabel status).

## Referensi

- Bogdanov, A. et al. (2007). *PRESENT: An Ultra-Lightweight Block Cipher.* CHES 2007, LNCS 4727, 450-466.
- ISO/IEC 29192-2 (varian 128-bit) -- cek sendiri vektor ujinya.
- Bellare, M. & Namprempre, C. (2000) untuk komposisi encrypt-then-MAC; Bellare, Kilian & Rogaway (2000) untuk CBC-MAC dan awalan panjang -- **periksa sitasi sebelum dipakai di skripsi**, saya menuliskannya dari ingatan.
