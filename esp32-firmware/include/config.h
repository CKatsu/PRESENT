#pragma once
// =============================================================================
// config.h -- konfigurasi firmware PRESENT streaming (ESP32-S3)
// =============================================================================
// SINKRONISASI KUNCI: nilai di bawah HARUS sama dengan benchmark-present-iot/config.py
// (KEYS[80]/KEYS[128]) -- jika tidak, receiver menolak semua paket (tag_mismatch).
// Kunci ini kunci UJI AKADEMIK, bukan rahasia produksi.
#define ENC_KEY_80_HEX  "0f1e2d3c4b5a69788796"
#define MAC_KEY_80_HEX  "a1b2c3d4e5f60718293a"
#define ENC_KEY_128_HEX "00112233445566778899aabbccddeeff"
#define MAC_KEY_128_HEX "ffeeddccbbaa99887766554433221100"

#ifndef PRESENT_KEY_BITS
#define PRESENT_KEY_BITS 80          // 80 atau 128 (variabel bebas penelitian)
#endif

#define DEVICE_ID "e001"             // <= 8 karakter agar payload 64 B muat
#define STREAM_SCENARIO_TAG "STREAM" // dipisah dari S1-S4 (device_sim.py) agar tidak tercampur
#ifndef PAYLOAD_TARGET_SIZE_BYTES
#define PAYLOAD_TARGET_SIZE_BYTES 64 // plaintext JSON + padding spasi (64/256/1024); override: -D...
#endif
#define MAX_PLAINTEXT_LEN 1024       // ukuran buffer statis (tanpa alokasi dinamis)
#define SEND_INTERVAL_MS 1000
#define ACK_TIMEOUT_MS 2000
#define SERIAL_BAUD 115200

// BME280 (GY-BME280) via I2C -- SESUAIKAN pin dengan board Anda.
#define BME280_SDA_PIN 8
#define BME280_SCL_PIN 9
#define BME280_I2C_ADDR_PRIMARY 0x76
#define BME280_I2C_ADDR_SECONDARY 0x77

// Data sintetis selama BME280 belum terdeteksi (sama dengan config.py -- ASUMSI, bukan kalibrasi)
#define SYN_TEMP_BASE 28.0f
#define SYN_TEMP_JIT 1.5f
#define SYN_HUM_BASE 65.0f
#define SYN_HUM_JIT 8.0f
#define SYN_PRES_BASE 1009.0f
#define SYN_PRES_JIT 2.0f

// Demo S4 opsional: tiap N pesan, balik 1 bit ciphertext SETELAH tag dihitung (0 = nonaktif)
#ifndef TAMPER_DEMO_EVERY_N_MESSAGES
#define TAMPER_DEMO_EVERY_N_MESSAGES 0
#endif
