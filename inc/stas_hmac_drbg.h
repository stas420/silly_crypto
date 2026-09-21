#ifndef STAS_HMAC_DRBG_H__
#define STAS_HMAC_DRBG_H__

#include "stas_common.h"

#include <stdint.h>


#define STAS_HMAC_DRBG_OUTLEN_BYTES (32U)


// typedef enum {
//     SEC_STRENGTH_112,
//     SEC_STRENGTH_128,
//     SEC_STRENGTH_192,
//     SEC_STRENGTH_256,
// } DRGBSecStrength;

typedef struct stas_HMACDRBGStateS {

    uint8_t         V[STAS_HMAC_DRBG_OUTLEN_BYTES],
                    K[STAS_HMAC_DRBG_OUTLEN_BYTES];

    uint64_t        reseed_ctr;

    // DRGBSecStrength sec_strength;

    // uint8_t         pred_resist;

} HMACDRBGState;


stasRet stas_HMAC_DRBG_instantiate(const uint8_t* const entropy_p, uint16_t entropy_len, const uint8_t* const nonce_p, uint16_t nonce_len,
                              const uint8_t* const personal_p, uint16_t personal_len, HMACDRBGState* state_p);

stasRet stas_HMAC_DRBG_generate(HMACDRBGState* state_p, uint8_t* bits_p, uint32_t bits_len, const uint8_t* const additional_p, uint16_t additional_len);

stasRet stas_HMAC_DRBG_uninstantiate(HMACDRBGState* state_p);

stasRet stas_HMAC_DRBG_easy_generate_once(uint8_t* output_p, uint32_t byte_len);

#endif // STAS_HMAC_DRBG_H__
