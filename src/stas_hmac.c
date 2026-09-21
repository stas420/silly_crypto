#include "stas_common.h"
#include "stas_hmac.h"
#include "stas_sha256.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/**
 * HMAC implementation basing on SHA-256 algo - as per FIPS 198-1, Section 4.
 */
uint8_t* stas_hmac_sha256(const uint8_t* const key_p, uint32_t key_len, const uint8_t* const data_p, uint32_t data_len) {
    // we work on B (STAS_SHA256_BLOCK_SIZE_BYTES) size, where the input is of L (key_len) size
    uint8_t* key0_p = (uint8_t*) calloc(STAS_SHA256_BLOCK_SIZE_BYTES, sizeof(uint8_t));

    if (!key0_p) {
        return NULL;
    }

    // step 2.
    if (key_len > STAS_SHA256_BLOCK_SIZE_BYTES) {
        uint8_t* key_hash = stas_sha256(key_p, key_len);

        if (!key_hash) {
            free(key0_p);
            return NULL;
        }

        (void) memcpy(key0_p, key_hash, STAS_SHA256_DGST_LEN_BYTES);
        free(key_hash);
    }
    // step 3.
    else if (key_len < STAS_SHA256_BLOCK_SIZE_BYTES) {
        (void) memcpy(key0_p, key_p, key_len);
    }
    // step 1.
    else {
        (void) memcpy(key0_p, key_p, STAS_SHA256_BLOCK_SIZE_BYTES);
    }

    uint8_t* res = NULL;

    // step 4.
    static const uint8_t ipad_byte = 0x36;
    uint8_t key0_ipad[STAS_SHA256_BLOCK_SIZE_BYTES] = { 0U };

    for (uint16_t i = 0U; i < STAS_SHA256_BLOCK_SIZE_BYTES; i++) {
        key0_ipad[i] = key0_p[i] ^ ipad_byte;
    }

    // step 5.
    const uint64_t ipad_stream_len = STAS_SHA256_BLOCK_SIZE_BYTES + data_len;
    uint8_t* ipad_stream = (uint8_t*) calloc(ipad_stream_len, sizeof(uint8_t));

    if (ipad_stream) {
        for (uint32_t i = 0U; i < STAS_SHA256_BLOCK_SIZE_BYTES; i++) {
            ipad_stream[i] = key0_ipad[i];
        }

        for (uint32_t i = 0U; i < data_len; i++) {
            ipad_stream[STAS_SHA256_BLOCK_SIZE_BYTES + i] = data_p[i];
        }

        // step 6.
        uint8_t* ipad_stream_hash = stas_sha256(ipad_stream, ipad_stream_len);

        if (ipad_stream_hash) {
            // step 7.
            static const uint8_t opad_byte = 0x5c;
            uint8_t key0_opad[STAS_SHA256_BLOCK_SIZE_BYTES] = { 0U };

            for (uint32_t i = 0U; i < STAS_SHA256_BLOCK_SIZE_BYTES; i++) {
                key0_opad[i] = key0_p[i] ^ opad_byte;
            }

            // step 8.
            const uint64_t opad_stream_len = STAS_SHA256_DGST_LEN_BYTES + STAS_SHA256_BLOCK_SIZE_BYTES;
            uint8_t* opad_stream = (uint8_t*) calloc(opad_stream_len, sizeof(uint8_t));

            if (opad_stream) {

                // I konw, different approach than earlier, works the same
                // which is cleaner? up to you
                (void) memcpy(opad_stream, key0_opad, STAS_SHA256_BLOCK_SIZE_BYTES);
                (void) memcpy(&opad_stream[STAS_SHA256_BLOCK_SIZE_BYTES], ipad_stream_hash, STAS_SHA256_DGST_LEN_BYTES);

                // step 9.
                res = stas_sha256(opad_stream, opad_stream_len);

                // clear (zero) memory for security considerations
                stas_secure_zero(opad_stream, opad_stream_len * sizeof(uint8_t));
                free(opad_stream);
            }

            // clear (zero) memory for security considerations
            stas_secure_zero(key0_opad, STAS_SHA256_BLOCK_SIZE_BYTES * sizeof(uint8_t));
        }

        // clear (zero) memory for security considerations
        stas_secure_zero(ipad_stream, ipad_stream_len * sizeof(uint8_t));
        stas_secure_zero(ipad_stream_hash, STAS_SHA256_DGST_LEN_BYTES * sizeof(uint8_t));

        free(ipad_stream);
        free(ipad_stream_hash);
    }

    // clear (zero) memory for security considerations
    stas_secure_zero(key0_ipad, STAS_SHA256_BLOCK_SIZE_BYTES * sizeof(uint8_t));
    stas_secure_zero(key0_p, STAS_SHA256_BLOCK_SIZE_BYTES * sizeof(uint8_t));

    free(key0_p);

    return res;
}
