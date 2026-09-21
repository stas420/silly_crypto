#include "stas_ifc_keygen.h"
#include "stas_common.h"
#include "stas_hmac_drbg.h"

#include <gmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#define STAS_IFC_KEYGEN_MIN_MOD_LEN_BITS (2048U)
#define STAS_IFC_KEYGEN_PRIMALITY_MIN_TESTS_BASE (25U)
#define STAS_IFC_KEYGEN_PRIMALITY_MIN_TESTS (5U + STAS_IFC_KEYGEN_PRIMALITY_MIN_TESTS_BASE)
#define STAS_IFC_KEYGEN_P_MAX_TRIES (5U)
#define STAS_IFC_KEYGEN_Q_MAX_TRIES (10U)
#define STAS_IFC_KEYGEN_SAFE_STOP_MAX (1000U)

static void stas_IFC_keygen_test_printf(mpz_t p, mpz_t q, unsigned long public_exp);

/**
 * Generation of primes p,q as per NIST FIPS 186-5
 * Chosen method A (App. A.1.3)
 */
stasRet stas_IFC_keygen_random_probable_primes(uint8_t* out_p_p, size_t* out_p_len_p, uint8_t* out_q_p, size_t* out_q_len_p, const uint32_t modulus_len_bits, const uint32_t public_exp) {
    stasRet ret = FAILURE;

    uint32_t priv_len_bits = modulus_len_bits / 2;
    uint32_t priv_len = priv_len_bits / STAS_CRYPTO_BYTE_LEN_BITS;

    // step. 1
    if ((modulus_len_bits < STAS_IFC_KEYGEN_MIN_MOD_LEN_BITS) || (out_p_p == NULL) || (out_q_p == NULL)) {
        ret = INVALID_ARG;
        return ret;
    }

    // step 2. -> skip

    // step 3. -> skip? my HMAC_DRBG already supports that

    // step 4.1. -> later

    // step 4.2. preps
    mpz_t p, q;
    mpz_init(p);
    mpz_init(q);
    mpz_set_ui(p, 0U);
    mpz_set_ui(q, 0U);

    uint8_t* p_bytes_p = NULL;
    p_bytes_p = (uint8_t*) calloc(priv_len, sizeof(uint8_t));

    if (p_bytes_p) {
        mpz_t p_bound, p_squared;
        mpz_init(p_bound);
        mpz_init(p_squared);
        mpz_ui_pow_ui(p_bound, 2, modulus_len_bits - 1);

        // step 4.1.
        for (uint64_t i = 0U; i < STAS_IFC_KEYGEN_P_MAX_TRIES * modulus_len_bits; i++) {
            uint64_t safe_stop = 0U;
            do {
                // step 4.2.
                ret = stas_HMAC_DRBG_easy_generate_once(p_bytes_p, priv_len);

                // step 4.2.1.
                if (ret == SUCCESS) {
                    p_bytes_p[0] |= 1 << 7U;
                    p_bytes_p[0] |= 1 << 6U;
                    p_bytes_p[priv_len - 1U] |= 1;
                    mpz_import(p, priv_len, 1, sizeof(uint8_t), 0, 0, p_bytes_p);

                    // step 4.3. -> skip
                    mpz_mul(p_squared, p, p);
                }

                safe_stop += 1;
            } while ((mpz_cmp(p_squared, p_bound) < 0) && (safe_stop < STAS_IFC_KEYGEN_SAFE_STOP_MAX));  //< step 4.4. equivalence

            stas_secure_zero(p_bytes_p, priv_len);

            if ((safe_stop == STAS_IFC_KEYGEN_SAFE_STOP_MAX) || (ret != SUCCESS)) {
                break;
            }

            ret = FAILURE;

            // step 4.5. preps
            mpz_t gcd, p_min;
            mpz_init(gcd);
            mpz_init(p_min);

            mpz_sub_ui(p_min, p, 1);
            mpz_gcd_ui(gcd, p_min, public_exp);

            // step 4.5.
            if (mpz_get_ui(gcd) == 1U) {
                // step 4.5.1, 4.5.2
                if (mpz_probab_prime_p(p, STAS_IFC_KEYGEN_PRIMALITY_MIN_TESTS) > 0) {
                    ret = SUCCESS;
                }
            }

            mpz_clear(gcd);
            mpz_clear(p_min);

            if (ret == SUCCESS) {
                break;
            }
        }

        mpz_clear(p_bound);
        mpz_clear(p_squared);

        free(p_bytes_p);
    }

    // step 5. preps
    if (ret == SUCCESS) {
        ret = FAILURE;

        uint8_t* q_bytes_p = NULL;
        q_bytes_p = (uint8_t*) calloc(priv_len, sizeof(uint8_t));

        if (q_bytes_p) {
            // step 5.1., 5.7., 5.8. equivalence
            // helper values for bounds and arithmetic checks in 5.4 and 5.5 steps
            mpz_t q_bound, q_squared, diff, diff_abs, diff_bound;
            mpz_init(q_bound);
            mpz_init(q_squared);
            mpz_init(diff);
            mpz_init(diff_bound);
            mpz_init(diff_abs);

            mpz_ui_pow_ui(q_bound, 2, modulus_len_bits - 1);
            mpz_ui_pow_ui(diff_bound, 2, (priv_len_bits - 100U));

            for (uint64_t i = 0U; i < STAS_IFC_KEYGEN_Q_MAX_TRIES * modulus_len_bits; i++) {
                uint64_t safe_stop = 0U;
                do {
                    // step 5.2.
                    ret = stas_HMAC_DRBG_easy_generate_once(q_bytes_p, priv_len);

                    // step 5.2.1.
                    if (ret == SUCCESS) {
                        q_bytes_p[0] |= 1 << 7U;
                        q_bytes_p[0] |= 1 << 6U;
                        q_bytes_p[priv_len - 1U] |= 1;

                        // step 5.3. -> skip
                        mpz_import(q, priv_len, 1, sizeof(uint8_t), 0, 0, q_bytes_p);
                        mpz_mul(q_squared, q, q);
                        mpz_sub(diff, p, q);
                        mpz_abs(diff_abs, diff);
                    }

                    safe_stop += 1;

                    // v steps 5.4. 5.5. equivalence
                } while(((mpz_cmp(q_squared, q_bound) < 0) || (mpz_cmp(diff_abs, diff_bound) < 1)) && (safe_stop < STAS_IFC_KEYGEN_SAFE_STOP_MAX));

                stas_secure_zero(q_bytes_p, priv_len);

                if ((safe_stop == STAS_IFC_KEYGEN_SAFE_STOP_MAX) || (ret != SUCCESS)) {
                    break;
                }

                ret = FAILURE;

                // step 5.6. prep
                mpz_t gcd, q_min;
                mpz_init(gcd);
                mpz_init(q_min);

                mpz_sub_ui(q_min, q, 1);
                mpz_gcd_ui(gcd, q_min, public_exp);

                // step 5.6.
                if (mpz_get_ui(gcd) == 1) {
                    // step 5.6.1, 5.6.2.
                    if (mpz_probab_prime_p(q, STAS_IFC_KEYGEN_PRIMALITY_MIN_TESTS) > 0) {
                        ret = SUCCESS;
                    }
                }

                mpz_clear(gcd);
                mpz_clear(q_min);

                if (ret == SUCCESS) {
                    break;
                }
            }

            mpz_clear(q_bound);
            mpz_clear(diff_bound);
            mpz_clear(q_squared);
            mpz_clear(diff);
            mpz_clear(diff_abs);

            free(q_bytes_p);
        }
    }


    stas_IFC_keygen_test_printf(p, q, public_exp);

    (void) mpz_export(out_p_p, out_p_len_p, 1, sizeof(uint8_t), 0, 0, p);
    (void) mpz_export(out_q_p, out_q_len_p, 1, sizeof(uint8_t), 0, 0, q);

    mpz_clear(p);
    mpz_clear(q);

    return ret;
}

static void stas_IFC_keygen_test_printf(mpz_t p, mpz_t q, unsigned long public_exp) {
    size_t p_len = mpz_sizeinbase(p, 2);
    size_t q_len = mpz_sizeinbase(q, 2);

    printf("p size: %lu \t q size: %lu \n", p_len, q_len);

    int cmp_res = mpz_cmp(p, q);

    printf("cmp res: %d\n", cmp_res);

    mpz_t c, m, m_prim, e, n;
    mpz_inits(c, m, m_prim, e, n, NULL);

    mpz_set_ui(m, 17648787);
    mpz_set_ui(e, public_exp);
    mpz_mul(n, p, q);
    mpz_powm(c, m, e, n);

    mpz_t lambda_n, d;
    mpz_init(lambda_n);
    mpz_init(d);

    /* lambda_n = lcm(p-1, q-1) */
    mpz_t p1, q1, g;
    mpz_init(p1); mpz_init(q1); mpz_init(g);
    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_gcd(g, p1, q1);
    mpz_mul(lambda_n, p1, q1);
    mpz_divexact(lambda_n, lambda_n, g);   /* lcm(a,b) = a*b / gcd(a,b) */

    int ok = mpz_invert(d, e, lambda_n);
    if (!ok) {
        /* e has no inverse mod lambda_n -- means gcd(e, lambda_n) != 1,
            which should never happen if you already checked gcd(e, p-1)=1
            and gcd(e, q-1)=1 during candidate generation */
        printf("e has no inverse : (((\n");
    }
    else {
        mpz_powm(m_prim, c, d, n);

        if (mpz_cmp(m, m_prim) == 0) {
            printf("msg comparinson OK\n");
        }
        else {
            printf("msg comp bad : ((\n");
        }
    }


    mpz_clears(c, m, m_prim, e, n, lambda_n, d, p1, q1, g, NULL);
}
