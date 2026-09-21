#ifndef STAS_SHA256_H__
#define STAS_SHA256_H__

#define STAS_SHA256_DGST_LEN_BITS    (256U)
#define STAS_SHA256_DGST_LEN_BYTES   (32U)
#define STAS_SHA256_BLOCK_SIZE_BITS  (512U)
#define STAS_SHA256_BLOCK_SIZE_BYTES (64U)

#include <stdint.h>

/**
 * @brief SHA256 implementation, as per FIPS 180-4
 *
 * @param data_p    Bytes to be hashed
 * @param data_len  Number of bytes to be hashed
 * @return          On success: NEWLY ALLOCATED SHA256 data buffer which must be freed by the user \
 *                  On failure: NULL
 */
uint8_t* stas_sha256(const uint8_t* const data, uint64_t data_len);

#endif
