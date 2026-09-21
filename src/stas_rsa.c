#include "stas_rsa.h"
#include "stas_common.h"
#include "stas_ifc_keygen.h"

#include <gmp.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#define STAS_ASN1_SEQUENCE_DEF_BYTE (0x30)
#define STAS_ASN1_INTEGER_DEF_BYTE  (0x02)

/*
    RSAPublicKey ::= SEQUENCE {
        modulus           INTEGER,  -- n
        publicExponent    INTEGER   -- e
    }

    RSAPrivateKey ::= SEQUENCE {
        version           Version,
        modulus           INTEGER,  -- n
        publicExponent    INTEGER,  -- e
        privateExponent   INTEGER,  -- d
        prime1            INTEGER,  -- p
        prime2            INTEGER,  -- q
        exponent1         INTEGER,  -- d mod (p-1)
        exponent2         INTEGER,  -- d mod (q-1)
        coefficient       INTEGER,  -- (inverse of q) mod p
        otherPrimeInfos   OtherPrimeInfos OPTIONAL
    }
*/

typedef struct stas_rsa_key_params {
    mpz_t n, e, d, p, q, dp, dq, q_inv;
} stasRsaKeyParams;

static void stasRsaKeyParams_init(stasRsaKeyParams* params_p) {
    mpz_inits(params_p->n, params_p->e, params_p->d, params_p->p, params_p->q, params_p->dp, params_p->dq, params_p->q_inv, NULL);
}

static void stasRsaKeyParams_clear(stasRsaKeyParams* params_p) {
    mpz_clears(params_p->n, params_p->e, params_p->d, params_p->p, params_p->q, params_p->dp, params_p->dq, params_p->q_inv, NULL);
}

static size_t stas_mpz_size_bytes(const mpz_t n) {
    return (mpz_sizeinbase(n, 2) + 7 / 8);
}

static stasRet stas_rsa_private_key_asn1(const stasRsaKeyParams* params_p, uint8_t** out_private_key_p, uint32_t* out_private_key_len_p) {
    stasRet ret = INVALID_ARG;

    if ((params_p == NULL) || (out_private_key_p == NULL) || (out_private_key_len_p == NULL)) {
        return ret;
    }

    ret = FAILURE;

    size_t tmp = 0U;
    tmp += stas_mpz_size_bytes(params_p->n);
    tmp += stas_mpz_size_bytes(params_p->e);
    tmp += stas_mpz_size_bytes(params_p->d);
    tmp += stas_mpz_size_bytes(params_p->p);
    tmp += stas_mpz_size_bytes(params_p->q);
    tmp += stas_mpz_size_bytes(params_p->dp);
    tmp += stas_mpz_size_bytes(params_p->dq);
    tmp += stas_mpz_size_bytes(params_p->q_inv);

    if (tmp > 0U) {


    }

    return ret;
}

stasRet stas_RSA_derive(void) {
    stasRet ret = FAILURE;

    const uint32_t primes_len_bytes = STAS_IFC_KEYGEN_RSA_2048_KEYLEN/2 / STAS_CRYPTO_BYTE_LEN_BITS;
    uint8_t p_prime[STAS_IFC_KEYGEN_RSA_2048_KEYLEN/2 / STAS_CRYPTO_BYTE_LEN_BITS];
    uint8_t q_prime[STAS_IFC_KEYGEN_RSA_2048_KEYLEN/2 / STAS_CRYPTO_BYTE_LEN_BITS];

    size_t p_len = 0U, q_len = 0U;

    stasRsaKeyParams params;
    stasRsaKeyParams_init(&params);

    ret = stas_IFC_keygen_random_probable_primes(p_prime, &p_len, q_prime, &q_len, STAS_IFC_KEYGEN_RSA_2048_KEYLEN, STAS_IFC_KEYGEN_DEFAULT_PUBLIC_EXP);

    if ((ret == SUCCESS) && (p_len == primes_len_bytes) && (q_len == primes_len_bytes)) {
        ret = FAILURE;

        mpz_t p_min, q_min, phi_n;
        mpz_inits(p_min, q_min, phi_n, NULL);

        mpz_import(params.p, primes_len_bytes, 1, sizeof(uint8_t), 0, 0, p_prime);
        mpz_import(params.q, primes_len_bytes, 1, sizeof(uint8_t), 0, 0, q_prime);

        mpz_mul(params.n, params.p, params.q);

        mpz_set_ui(params.e, STAS_IFC_KEYGEN_DEFAULT_PUBLIC_EXP);

        mpz_sub_ui(p_min, params.p, 1);
        mpz_sub_ui(q_min, params.q, 1);
        mpz_mul(phi_n, p_min, q_min);

        if (mpz_invert(params.d, params.e, phi_n) != 0) {

            mpz_mod(params.dp, params.d, p_min);

            mpz_mod(params.dq, params.d, q_min);

            if (mpz_invert(params.q_inv, params.q, params.p) != 0) {
                ret = SUCCESS;
            }
        }

        if (ret == SUCCESS) {
            uint8_t* private_key_p = NULL;
            uint32_t private_key_len = 0U;

            ret = stas_rsa_private_key_asn1(&params, &private_key_p, &private_key_len);
        }

        mpz_clears(p_min, q_min, phi_n, NULL);
    }

    stasRsaKeyParams_clear(&params);

    return ret;
}
