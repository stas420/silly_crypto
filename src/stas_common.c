#include "stas_common.h"

#include <stdint.h>

void stas_secure_zero(void* data, uint64_t len) {
    volatile uint8_t* p = (volatile uint8_t*) data;

    while (len > 0) {
        *p = 0U;
        p++;
        len--;
    }
}
