// Harness PC: menjalankan src/main.cpp ASLI (setup()/loop()) dengan stub Arduino.
// Keluaran stdout = persis apa yang akan ditulis firmware ke Serial (baris "PRS1:" & "#").
// ACK dari stub selalu "accepted" HANYA agar loop firmware maju; keputusan sebenarnya
// diverifikasi oleh receiver Python (tests/test_firmware_host.py).
#include <Arduino.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <Wire.h>
#include <WiFi.h>
#include <stdlib.h>

HostSerial Serial;
TwoWire Wire;
WiFiClass WiFi;
static uint32_t g_clock = 0;
static uint64_t g_rng = 0x1234567890ABCDEFULL;
uint32_t millis() { g_clock += 300; return g_clock; }
void delay(uint32_t ms) { g_clock += ms; }
uint32_t esp_random() { g_rng = g_rng * 6364136223846793005ULL + 1442695040888963407ULL; return (uint32_t)(g_rng >> 33); }
int64_t esp_timer_get_time() { return (int64_t)g_clock * 1000; }

void HostSerial::on_line() {
    if (strncmp(linebuf, "PRS1:", 5) != 0) return;
    const char *p = strstr(linebuf, "\"seq\":");
    if (!p) return;
    unsigned long seq = strtoul(p + 6, nullptr, 10);
    rx_len = (size_t)snprintf(rx, sizeof rx, "PRS1:{\"ack\":1,\"device_id\":\"e001\",\"seq\":%lu,\"run_id\":\"x\",\"accepted\":true}\n", seq);
    rx_pos = 0;
}

void setup();
void loop();
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 8;
    setup();
    for (int i = 0; i < n * 4; i++) loop();
    return 0;
}
