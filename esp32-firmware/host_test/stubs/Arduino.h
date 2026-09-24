#pragma once
// STUB Arduino minimal untuk menjalankan/syntax-check src/*.cpp di PC (BUKAN Arduino asli).
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t millis();
void delay(uint32_t ms);

struct HostSerial {
    char linebuf[4096];
    size_t ln = 0;
    char rx[512];
    size_t rx_len = 0, rx_pos = 0;
    void begin(unsigned long) {}
    void flush() {}
    void on_line();
    size_t write(const uint8_t *p, size_t n) {
        fwrite(p, 1, n, stdout);
        for (size_t i = 0; i < n; i++) {
            if (p[i] == '\n') { linebuf[ln < sizeof linebuf ? ln : sizeof linebuf - 1] = 0; on_line(); ln = 0; }
            else if (ln < sizeof linebuf - 1) linebuf[ln++] = (char)p[i];
        }
        return n;
    }
    size_t write(uint8_t c) { return write(&c, 1); }
    size_t print(const char *s) { return write((const uint8_t *)s, strlen(s)); }
    size_t print(char c) { return write((uint8_t)c); }
    size_t print(int v) { char b[24]; snprintf(b, sizeof b, "%d", v); return print(b); }
    size_t print(unsigned long v) { char b[24]; snprintf(b, sizeof b, "%lu", v); return print(b); }
    size_t println() { return print("\n"); }
    size_t println(const char *s) { size_t n = print(s); return n + print("\n"); }
    size_t println(int v) { size_t n = print(v); return n + print("\n"); }
    int printf(const char *fmt, ...) __attribute__((format(printf, 2, 3))) {
        char b[1024]; va_list ap; va_start(ap, fmt); int n = vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
        write((const uint8_t *)b, (size_t)n); return n;
    }
    int available() { return (int)(rx_len - rx_pos); }
    int read() { return rx_pos < rx_len ? (unsigned char)rx[rx_pos++] : -1; }
};
extern HostSerial Serial;
