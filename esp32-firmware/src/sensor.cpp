#include "sensor.h"
#include "config.h"
#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_BME280.h>
#include <esp_system.h>
#include <math.h>

static Adafruit_BME280 g_bme;

// jitter dari RNG hardware -- BUKAN untuk keperluan kriptografi
static float rand_jitter(float range) {
    int32_t r = (int32_t)(esp_random() % 20001) - 10000;
    return (r / 10000.0f) * range;
}
static float clampf(float v, float lo, float hi) { return v < lo ? lo : (v > hi ? hi : v); }

void SensorSource::begin() {
    Wire.begin(BME280_SDA_PIN, BME280_SCL_PIN);
    real_ok_ = g_bme.begin(BME280_I2C_ADDR_PRIMARY, &Wire) || g_bme.begin(BME280_I2C_ADDR_SECONDARY, &Wire);
    if (real_ok_) {
        g_bme.setSampling(Adafruit_BME280::MODE_NORMAL, Adafruit_BME280::SAMPLING_X2, Adafruit_BME280::SAMPLING_X16,
                          Adafruit_BME280::SAMPLING_X1, Adafruit_BME280::FILTER_OFF);
    }
}

SensorReading SensorSource::readSynthetic() {
    t_ = clampf(t_ + rand_jitter(0.15f), SYN_TEMP_BASE - SYN_TEMP_JIT, SYN_TEMP_BASE + SYN_TEMP_JIT);
    h_ = clampf(h_ + rand_jitter(0.8f), SYN_HUM_BASE - SYN_HUM_JIT, SYN_HUM_BASE + SYN_HUM_JIT);
    p_ = clampf(p_ + rand_jitter(0.1f), SYN_PRES_BASE - SYN_PRES_JIT, SYN_PRES_BASE + SYN_PRES_JIT);
    return SensorReading{t_, h_, p_, true};
}

SensorReading SensorSource::read() {
    if (real_ok_) {
        SensorReading r{g_bme.readTemperature(), g_bme.readHumidity(), g_bme.readPressure() / 100.0f, false};
        if (!isnan(r.temp_c) && !isnan(r.hum_pct) && !isnan(r.pres_hpa)) return r;
        // gangguan I2C sesaat: turun ke sintetis HANYA untuk sampel ini, tetap berlabel sintetis
    }
    return readSynthetic();
}
