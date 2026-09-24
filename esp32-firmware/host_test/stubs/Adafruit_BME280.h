#pragma once
// STUB: sensor TIDAK terdeteksi (meniru kondisi BME280 belum terpasang)
#include "Wire.h"
class Adafruit_BME280 {
public:
    enum sensor_mode { MODE_NORMAL };
    enum sensor_sampling { SAMPLING_X1, SAMPLING_X2, SAMPLING_X16 };
    enum sensor_filter { FILTER_OFF };
    bool begin(int, TwoWire *) { return false; }
    void setSampling(sensor_mode, sensor_sampling, sensor_sampling, sensor_sampling, sensor_filter) {}
    float readTemperature() { return 0; }
    float readHumidity() { return 0; }
    float readPressure() { return 0; }
};
