#pragma once
// payload.h -- payload JSON ringkas, IDENTIK dengan benchmark-present-iot/payload_format.py:
//   {"id":"e001","q":12,"t":28.51,"h":64.2,"p":1009.3,"s":1}   + padding spasi sampai target
//   s = 1 sintetis, 0 sensor fisik (label JUJUR di setiap paket).
#include <stddef.h>
#include <stdint.h>

struct SensorReading {
    float temp_c;
    float hum_pct;
    float pres_hpa;
    bool synthetic;
};

// Menulis tepat `target` byte ke out (tanpa NUL-terminator). Return target, atau 0 jika
// JSON minimal > target atau out_cap < target.
size_t build_sensor_payload(uint8_t *out, size_t out_cap, const char *device_id, uint32_t seq,
                            const SensorReading &r, size_t target);
