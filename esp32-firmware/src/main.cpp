// =============================================================================
// main.cpp -- Firmware streaming sensor suhu terenkripsi (ESP32-S3)
//   PRESENT-80/128 CBC (PKCS#7) + PRESENT-CBC-MAC (encrypt-then-MAC, kunci ENC & MAC terpisah)
// Alur: baca sensor (BME280 fisik / sintetis) -> payload JSON -> enkripsi + tag -> kirim
//       (UART/USB-Serial ATAU MQTT, pilih environment PlatformIO) -> tunggu ACK receiver.
// Format paket = envelope JSON yang sama dengan benchmark-present-iot/receiver_server.py
// (lihat docstring receiver_server.py). Baris UART berawalan "PRS1:" = protokol, berawalan
// "#" = log (diabaikan receiver). Field "enc_us" = waktu kripto (CBC-encrypt + CBC-MAC)
// yang DIUKUR di ESP32 dengan esp_timer (mikrodetik) -- dicatat receiver di server_all.csv.
// Firmware TIDAK mengotomasi S1-S4 (itu device_sim.py); ini mode streaming untuk membuktikan
// pipeline end-to-end di hardware & mengecek data sensor.
// =============================================================================
#include <Arduino.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <stdio.h>
#include <string.h>

#include "b64.h"
#include "config.h"
#include "payload.h"
#include "present.h"
#include "sensor.h"

#ifdef PRESENT_TRANSPORT_MQTT
#include <PubSubClient.h>
#include <WiFi.h>
#include "secrets.h"
#endif

#if PRESENT_KEY_BITS == 80
#define KEY_LEN 10
#define ENC_HEX ENC_KEY_80_HEX
#define MAC_HEX MAC_KEY_80_HEX
#elif PRESENT_KEY_BITS == 128
#define KEY_LEN 16
#define ENC_HEX ENC_KEY_128_HEX
#define MAC_HEX MAC_KEY_128_HEX
#else
#error "PRESENT_KEY_BITS harus 80 atau 128"
#endif

static present_ctx_t g_enc, g_mac;
static SensorSource g_sensor;
static uint32_t g_seq = 0;
static uint32_t g_last_send_ms = 0;
static char g_run_id[9];

// Buffer statis (tanpa alokasi dinamis)
static uint8_t g_pt[MAX_PLAINTEXT_LEN];
static uint8_t g_ct[MAX_PLAINTEXT_LEN + 8];
static char g_ct_b64[((MAX_PLAINTEXT_LEN + 8 + 2) / 3) * 4 + 4];
static char g_line[sizeof(g_ct_b64) + 320];

static void fatal_halt(const char *msg) {
    while (true) {                       // lebih baik berhenti daripada menghasilkan data tidak valid
        Serial.println(msg);
        delay(2000);
    }
}

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t n) {
    if (strlen(hex) != n * 2) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

// ------------------------------------------------------------------ transport
#ifdef PRESENT_TRANSPORT_MQTT
static WiFiClient g_wifi;
static PubSubClient g_mqtt(g_wifi);
static volatile bool g_ack_seen = false, g_ack_accepted = false;
static char g_ack_needle[32];

static void mqtt_on_message(char *, uint8_t *payload, unsigned int len) {
    char buf[320];
    unsigned n = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
    memcpy(buf, payload, n);
    buf[n] = '\0';
    if (strstr(buf, "\"ack\":1") && strstr(buf, g_ack_needle)) {
        g_ack_accepted = strstr(buf, "\"accepted\":true") != nullptr;
        g_ack_seen = true;
    }
}

static void mqtt_ensure() {
    if (WiFi.status() != WL_CONNECTED) {
        WiFi.mode(WIFI_STA);
        WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
        Serial.print("# [wifi] menyambung");
        while (WiFi.status() != WL_CONNECTED) { delay(400); Serial.print("."); }
        Serial.println(" OK");
    }
    while (!g_mqtt.connected()) {
        char cid[32];
        snprintf(cid, sizeof cid, "present-%s-%s", DEVICE_ID, g_run_id);
        if (g_mqtt.connect(cid)) {
            char t[48];
            snprintf(t, sizeof t, "present/%s/ack", DEVICE_ID);
            g_mqtt.subscribe(t);
        } else {
            delay(1000);
        }
    }
}

static void transport_begin() {
    g_mqtt.setServer(MQTT_BROKER_HOST, MQTT_BROKER_PORT);
    g_mqtt.setBufferSize(2048);
    g_mqtt.setCallback(mqtt_on_message);
    mqtt_ensure();
    Serial.println("# [ok] MQTT tersambung ke broker");
}

static bool transport_send(const char *json, size_t len) {
    mqtt_ensure();
    char t[48];
    snprintf(t, sizeof t, "present/%s/data", DEVICE_ID);
    return g_mqtt.publish(t, (const uint8_t *)json, (unsigned int)len);
}

static bool transport_wait_ack(uint32_t seq, uint32_t timeout_ms, bool *accepted) {
    snprintf(g_ack_needle, sizeof g_ack_needle, "\"seq\":%lu,", (unsigned long)seq);
    g_ack_seen = false;
    uint32_t t0 = millis();
    while (millis() - t0 < timeout_ms && !g_ack_seen) g_mqtt.loop();
    *accepted = g_ack_accepted;
    return g_ack_seen;
}
#else  // ---------------------------------------------------------------- UART
static void transport_begin() { /* Serial sudah dibuka di setup() */ }

static bool transport_send(const char *json, size_t len) {
    Serial.print("PRS1:");
    Serial.write((const uint8_t *)json, len);
    Serial.print('\n');
    Serial.flush();
    return true;
}

static bool transport_wait_ack(uint32_t seq, uint32_t timeout_ms, bool *accepted) {
    char needle[32], buf[320];
    snprintf(needle, sizeof needle, "\"seq\":%lu,", (unsigned long)seq);
    size_t n = 0;
    uint32_t t0 = millis();
    while (millis() - t0 < timeout_ms) {
        while (Serial.available()) {
            char c = (char)Serial.read();
            if (c == '\n') {
                buf[n < sizeof(buf) ? n : sizeof(buf) - 1] = '\0';
                bool hit = strncmp(buf, "PRS1:", 5) == 0 && strstr(buf, "\"ack\":1") && strstr(buf, needle);
                if (hit) {
                    *accepted = strstr(buf, "\"accepted\":true") != nullptr;
                    return true;
                }
                n = 0;
            } else if (n < sizeof(buf) - 1) {
                buf[n++] = c;
            }
        }
    }
    return false;
}
#endif

// ---------------------------------------------------------------------- setup
void setup() {
    Serial.begin(SERIAL_BAUD);
    delay(1500);
    Serial.println();
    Serial.println("# ================================================================");
    Serial.println("# Firmware streaming PRESENT-CBC + PRESENT-CBC-MAC (ESP32-S3)");
    Serial.print("# key=");
    Serial.print(PRESENT_KEY_BITS);
    Serial.println("-bit | baris 'PRS1:' = protokol, '#' = log");
    Serial.println("# ================================================================");

    if (!present_self_test())
        fatal_halt("# [FATAL] KAT PRESENT-80 GAGAL -- implementasi tidak sesuai spesifikasi. Firmware DIHENTIKAN.");
    Serial.println("# [ok] KAT resmi PRESENT-80 (Bogdanov et al. 2007): PASSED");

    uint8_t ek[16], mk[16];
    if (!hex_to_bytes(ENC_HEX, ek, KEY_LEN) || !hex_to_bytes(MAC_HEX, mk, KEY_LEN))
        fatal_halt("# [FATAL] kunci di include/config.h tidak valid (panjang hex salah).");
    present_key_schedule(&g_enc, ek, KEY_LEN);
    present_key_schedule(&g_mac, mk, KEY_LEN);
    Serial.println("# [ok] key schedule ENC & MAC selesai");

    snprintf(g_run_id, sizeof g_run_id, "%08lx", (unsigned long)esp_random());
    g_sensor.begin();
    Serial.print("# [ok] sumber sensor: ");
    Serial.println(g_sensor.usingRealSensor() ? "BME280 FISIK terdeteksi" : "SINTETIS (BME280 belum terpasang/terdeteksi)");
    transport_begin();
    Serial.println("# Mulai streaming...");
}

// -------------------------------------------------------------------- kirim 1 pesan
static void send_message(bool tamper_demo) {
    SensorReading r = g_sensor.read();
    size_t pt_len = build_sensor_payload(g_pt, sizeof g_pt, DEVICE_ID, g_seq, r, PAYLOAD_TARGET_SIZE_BYTES);
    if (pt_len == 0) {
        Serial.println("# [warn] payload gagal dibuat (target terlalu kecil / buffer kurang) -- dilewati");
        return;
    }
    uint8_t iv[8];
    for (int i = 0; i < 8; i++) iv[i] = (uint8_t)(esp_random() & 0xFF);   // IV baru tiap pesan

    int64_t t0 = esp_timer_get_time();                                    // ukur HANYA kripto
    size_t ct_len = present_cbc_encrypt(&g_enc, iv, g_pt, pt_len, g_ct, sizeof g_ct);
    uint8_t tag[8];
    if (ct_len) present_tag_iv_ct(&g_mac, iv, g_ct, ct_len, tag);
    uint32_t enc_us = (uint32_t)(esp_timer_get_time() - t0);
    if (ct_len == 0) {
        Serial.println("# [warn] enkripsi gagal (buffer)");
        return;
    }

    const char *cond = "normal", *tv = "";
    if (tamper_demo) {                     // penyerang di jalur: balik 1 bit ciphertext setelah tag dihitung
        g_ct[0] ^= 0x01;
        cond = "tampered";
        tv = "flip_ciphertext_bit";
    }

    char iv_hex[17], tag_b64[16];
    for (int i = 0; i < 8; i++) snprintf(iv_hex + 2 * i, 3, "%02x", iv[i]);
    b64_encode(g_ct_b64, sizeof g_ct_b64, g_ct, ct_len);
    b64_encode(tag_b64, sizeof tag_b64, tag, 8);

    int n = snprintf(g_line, sizeof g_line,
                     "{\"device_id\":\"%s\",\"seq\":%lu,\"scenario\":\"%s\",\"condition\":\"%s\",\"tv\":\"%s\","
                     "\"run_id\":\"%s\",\"key_bits\":%d,\"iv\":\"%s\",\"ct\":\"%s\",\"tag\":\"%s\",\"enc_us\":%lu}",
                     DEVICE_ID, (unsigned long)g_seq, STREAM_SCENARIO_TAG, cond, tv, g_run_id, PRESENT_KEY_BITS,
                     iv_hex, g_ct_b64, tag_b64, (unsigned long)enc_us);
    if (n <= 0 || (size_t)n >= sizeof g_line) {
        Serial.println("# [warn] envelope melebihi buffer -- dilewati");
        return;
    }
    uint32_t t_send = millis();
    transport_send(g_line, (size_t)n);
    bool accepted = false;
    bool got = transport_wait_ack(g_seq, ACK_TIMEOUT_MS, &accepted);
    Serial.printf("# seq=%lu T=%.2fC RH=%.1f%% P=%.1fhPa [%s] enc+mac=%luus ct=%uB %s rtt=%lums\n",
                  (unsigned long)g_seq, r.temp_c, r.hum_pct, r.pres_hpa, r.synthetic ? "SINTETIS" : "SENSOR-FISIK",
                  (unsigned long)enc_us, (unsigned)ct_len, got ? (accepted ? "ACK:DITERIMA" : "ACK:DITOLAK") : "TANPA-ACK",
                  (unsigned long)(millis() - t_send));
    g_seq++;
}

void loop() {
    uint32_t now = millis();
    if (now - g_last_send_ms >= SEND_INTERVAL_MS) {
        g_last_send_ms = now;
        bool demo = (TAMPER_DEMO_EVERY_N_MESSAGES > 0) && (((g_seq + 1) % TAMPER_DEMO_EVERY_N_MESSAGES) == 0);
        send_message(demo);
    }
}
