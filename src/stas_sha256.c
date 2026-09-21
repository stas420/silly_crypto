/**
 * as per NIST FIPS 180-4
 */

#include "stas_sha256.h"

#include <stdlib.h>
#include <string.h>

// pardon me, too lazy to fix all the magic numbers, there are too many in the doc
#define SHA256_BYTE_LEN_BITS    (8U)
#define SHA256_WORD_WIDTH_BITS  (32U)
#define SHA256_CONSTANTS_COUNT  (64U)

/**
 * Array of predefined algorithm constants, as in Subsection 4.2.2
 */
static const uint32_t sha256_constants[SHA256_CONSTANTS_COUNT] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


/* Helper functions, as defined in Subsection 4.1.2 */

static uint32_t sha256_ch(uint32_t x, uint32_t y, uint32_t z) {
    return ((x & y) ^ ((~x) & z));
}

static uint32_t sha256_maj(uint32_t x, uint32_t y, uint32_t z) {
    return ((x & y) ^ (x & z) ^ (y & z));
}

static uint32_t sha256_rotr(uint32_t x, uint32_t n) {
    return ((x >> n) | ((x << (SHA256_WORD_WIDTH_BITS - n))));
}

static uint32_t sha256_big_sigma_0_256(uint32_t x) {
    return sha256_rotr(x, 2U) ^ sha256_rotr(x, 13U) ^ sha256_rotr(x, 22U);
}

static uint32_t sha256_big_sigma_1_256(uint32_t x) {
    return sha256_rotr(x, 6U) ^ sha256_rotr(x, 11U) ^ sha256_rotr(x, 25U);
}

static uint32_t sha256_small_sigma_0_256(uint32_t x) {
    return sha256_rotr(x, 7U) ^ sha256_rotr(x, 18U) ^ (x >> 3U);
}

static uint32_t sha256_small_sigma_1_256(uint32_t x) {
    return sha256_rotr(x, 17U) ^ sha256_rotr(x, 19U) ^ (x >> 10U);
}

/**
 * @param data_p Bytes to be hashed
 * @param data_len Number of bytes to be hashed
 * @return On success: NEWLY ALLOCATED SHA256 data buffer which must be freed by the user \
 *         On failure: NULL
 */
uint8_t* stas_sha256(const uint8_t* const data_p, uint64_t data_len) {
    if ((data_len == 0U) || (data_p == NULL)) {
        return NULL;
    }

    // allocate buffer for message with padding, where msg_len + padding_len = 0 mod 512
    //
    // determining the buffer with padding length comes to aligning it to k * 64B,
    // which can be simply done with this little funny arithmetic trick
    uint64_t buffer_len = ((data_len + 9U + (STAS_SHA256_BLOCK_SIZE_BYTES - 1U))
                          / STAS_SHA256_BLOCK_SIZE_BYTES) * STAS_SHA256_BLOCK_SIZE_BYTES;

    uint8_t* buffer_p = (uint8_t*) calloc(sizeof(uint8_t), buffer_len);
    (void) memcpy(buffer_p, data_p, data_len);

    // set first bit in the padding as 1
    buffer_p[data_len] |= 1 << 7U;

    // set last 8 bytes to binary representation of the msg_len in MSB
    buffer_p[buffer_len - 8U] = (uint8_t)
                                (((uint64_t) (data_len * SHA256_BYTE_LEN_BITS)) >> (SHA256_BYTE_LEN_BITS * 7U));

    buffer_p[buffer_len - 7U] = (uint8_t)
                                (((uint64_t) (data_len * SHA256_BYTE_LEN_BITS)) >> (SHA256_BYTE_LEN_BITS * 6U));

    buffer_p[buffer_len - 6U] = (uint8_t)
                                (((uint64_t) (data_len * SHA256_BYTE_LEN_BITS)) >> (SHA256_BYTE_LEN_BITS * 5U));

    buffer_p[buffer_len - 5U] = (uint8_t)
                                (((uint64_t) (data_len * SHA256_BYTE_LEN_BITS)) >> (SHA256_BYTE_LEN_BITS * 4U));

    buffer_p[buffer_len - 4U] = (uint8_t)
                                (((uint64_t) (data_len * SHA256_BYTE_LEN_BITS)) >> (SHA256_BYTE_LEN_BITS * 3U));

    buffer_p[buffer_len - 3U] = (uint8_t)
                                (((uint64_t) (data_len * SHA256_BYTE_LEN_BITS)) >> (SHA256_BYTE_LEN_BITS * 2U));

    buffer_p[buffer_len - 2U] = (uint8_t)
                                (((uint64_t) (data_len * SHA256_BYTE_LEN_BITS)) >> (SHA256_BYTE_LEN_BITS * 1U));

    buffer_p[buffer_len - 1U] = (uint8_t)
                                (((uint64_t) (data_len * SHA256_BYTE_LEN_BITS)));


    // prepare
    uint32_t message_schedule[64U] = { 0 };
    // initial hash values, as in [TODO: add section specifier]
    uint32_t hashes[8U] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };

    // working variables
    uint32_t a = 0U, b = 0U, c = 0U, d = 0U,
             e = 0U, f = 0U, g = 0U, h = 0U;

    // temporary words used
    uint32_t t1 = 0U, t2 = 0U;

    // the algo
    for (uint64_t i = 0U; i < (buffer_len / 64U); i++) {

        // 1. prepare message schedule
        for (uint8_t t = 0U; t < 16U; t++) {
            message_schedule[t] = ((uint32_t) buffer_p[i * 64U + t * 4U + 0U] << 24U)
                                | ((uint32_t) buffer_p[i * 64U + t * 4U + 1U] << 16U)
                                | ((uint32_t) buffer_p[i * 64U + t * 4U + 2U] << 8U)
                                | ((uint32_t) buffer_p[i * 64U + t * 4U + 3U]);
        }

        for (uint8_t t = 16U; t < 64U; t++) {
            message_schedule[t] = sha256_small_sigma_1_256(message_schedule[t - 2U])
                                  + message_schedule[t - 7U]
                                  + sha256_small_sigma_0_256(message_schedule[t - 15U])
                                  + message_schedule[t - 16U];
        }

        // 2. initialize working vars
        a = hashes[0U];
        b = hashes[1U];
        c = hashes[2U];
        d = hashes[3U];
        e = hashes[4U];
        f = hashes[5U];
        g = hashes[6U];
        h = hashes[7U];

        // 3. the loop
        for (uint8_t t = 0U; t <= 63U; t++) {
            t1 = h + sha256_big_sigma_1_256(e) + sha256_ch(e, f, g)
                 + sha256_constants[t] + message_schedule[t];

            t2 = sha256_big_sigma_0_256(a) + sha256_maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        // 4. computate the hashes
        hashes[0U] = a + hashes[0U];
        hashes[1U] = b + hashes[1U];
        hashes[2U] = c + hashes[2U];
        hashes[3U] = d + hashes[3U];
        hashes[4U] = e + hashes[4U];
        hashes[5U] = f + hashes[5U];
        hashes[6U] = g + hashes[6U];
        hashes[7U] = h + hashes[7U];
    }

    uint8_t* out_p = (uint8_t*) calloc(sizeof(uint8_t), STAS_SHA256_DGST_LEN_BYTES);

    for (uint8_t i = 0U; i < 8U; i++) {
        out_p[i * 4U + 0U] = (uint8_t)(hashes[i] >> 24U);
        out_p[i * 4U + 1U] = (uint8_t)(hashes[i] >> 16U);
        out_p[i * 4U + 2U] = (uint8_t)(hashes[i] >>  8U);
        out_p[i * 4U + 3U] = (uint8_t)(hashes[i]);
    }

    free(buffer_p);

    return out_p;
}
