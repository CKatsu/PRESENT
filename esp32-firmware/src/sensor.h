#pragma once
// sensor.h -- BME280 fisik (bila terdeteksi) dengan FALLBACK OTOMATIS ke data sintetis.
// Setiap pembacaan diberi label synthetic true/false -> tidak pernah menyamar sebagai sensor asli.
// Begitu GY-BME280 terpasang & terdeteksi di I2C, firmware beralih ke pembacaan fisik tanpa
// mengubah kode/struktur data (payload, CSV, SQLite tetap sama; hanya s=0).
#include "payload.h"

class SensorSource {
public:
    void begin();
    SensorReading read();
    bool usingRealSensor() const { return real_ok_; }

private:
    bool real_ok_ = false;
    float t_ = 28.0f, h_ = 65.0f, p_ = 1009.0f;   // state random-walk sintetis
    SensorReading readSynthetic();
};
