#pragma once
// STUB untuk syntax-check jalur MQTT saja
#include <stdint.h>
#include "WiFi.h"
class PubSubClient {
public:
    explicit PubSubClient(WiFiClient &) {}
    void setServer(const char *, uint16_t) {}
    bool setBufferSize(uint16_t) { return true; }
    void setCallback(void (*)(char *, uint8_t *, unsigned int)) {}
    bool connected() { return true; }
    bool connect(const char *) { return true; }
    bool subscribe(const char *) { return true; }
    bool publish(const char *, const uint8_t *, unsigned int) { return true; }
    bool loop() { return true; }
};
