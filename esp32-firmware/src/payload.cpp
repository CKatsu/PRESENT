#include "payload.h"
#include <stdio.h>
#include <string.h>

size_t build_sensor_payload(uint8_t *out, size_t out_cap, const char *device_id, uint32_t seq,
                            const SensorReading &r, size_t target) {
    if (target > out_cap) return 0;
    char body[128];
    int n = snprintf(body, sizeof(body), "{\"id\":\"%s\",\"q\":%lu,\"t\":%.2f,\"h\":%.1f,\"p\":%.1f,\"s\":%d}",
                     device_id, (unsigned long)seq, (double)r.temp_c, (double)r.hum_pct, (double)r.pres_hpa,
                     r.synthetic ? 1 : 0);
    if (n <= 0 || (size_t)n >= sizeof(body) || (size_t)n > target) return 0;
    memcpy(out, body, (size_t)n);
    memset(out + n, ' ', target - (size_t)n);
    return target;
}
