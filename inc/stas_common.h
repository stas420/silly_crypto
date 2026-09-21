#ifndef STAS_COMMON_H__
#define STAS_COMMON_H__

#include <stdint.h>

#define STAS_CRYPTO_BYTE_LEN_BITS (8U)

void stas_secure_zero(void* data, uint64_t len);

typedef enum {
    SUCCESS     = 0x00,
    INVALID_ARG = 0x01,
    FAILURE     = 0x02,
} stasRet;

#endif // STAS_COMMON_H__
