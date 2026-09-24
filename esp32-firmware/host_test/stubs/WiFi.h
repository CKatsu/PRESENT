#pragma once
// STUB untuk syntax-check jalur MQTT saja
#include <stdint.h>
enum { WL_CONNECTED = 3 };
enum { WIFI_STA = 1 };
struct WiFiClient {};
struct WiFiClass { int status() { return WL_CONNECTED; } void mode(int) {} void begin(const char *, const char *) {} };
extern WiFiClass WiFi;
