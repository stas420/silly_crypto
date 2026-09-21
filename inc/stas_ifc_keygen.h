#ifndef STAS_IFC_KEYGEN_H__
#define STAS_IFC_KEYGEN_H__

#include "stas_common.h"
#include <stdlib.h>

#define STAS_IFC_KEYGEN_DEFAULT_PUBLIC_EXP (65537U)
#define STAS_IFC_KEYGEN_RSA_2048_KEYLEN (2048U)
#define STAS_IFC_KEYGEN_RSA_3072_KEYLEN (3072U)
#define STAS_IFC_KEYGEN_RSA_4096_KEYLEN (4096U)

stasRet stas_IFC_keygen_random_probable_primes(uint8_t* out_p_p, size_t* out_p_len_p, uint8_t* out_q_p, size_t* out_q_len_p, const uint32_t modulus_len_bits, const uint32_t public_exp);

#endif // STAS_IFC_KEYGEN_H__
