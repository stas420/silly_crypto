#include "stas_common.h"
#include "stas_hmac.h"
#include "stas_sha256.h"
#include "stas_hmac_drbg.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STAS_DRBG_SEC_STRENGTH_112 (112U)
#define STAS_DRBG_SEC_STRENGTH_128 (128U)
#define STAS_DRBG_SEC_STRENGTH_192 (192U)
#define STAS_DRBG_SEC_STRENGTH_256 (256U)

#define STAS_HMAC_DRBG_RESEED_INT               (2U)
#define STAS_HMAC_DRBG_ENTROPY_LEN              (64U)
#define STAS_HMAC_DRBG_MAX_BYTES_PER_REQUEST    (65536U)
#define STAS_HMAC_DRBG_DEV_URAND_STR            ("/dev/urandom")

/**
 * As specified in NIST SP 800-90A - HMAC_DRGB using SHA-256 (for now), basing on HMAC specs from FIPS 198-1
 *
 * Security strengths for asymmetric-key algos:
 * 112 - IFC(RSA) k = 2048
 * 128 - IFC(RSA) k = 3072
 * 192 - IFC(RSA) k = 7680
 * 256 - IFC(RSA) k = 15360
 *
 * Maximum security strengths for hash-based key derivation functions (e.g. HMAC)
 * >= 256 for SHA-256, SHA-512 ...
 *
 * Output block len (outlen):
 * 256 for SHA-256
 * 512 for SHA-512
 *
 * Required minimum entropy and entropy length (min_length): security_strength
 *
 * Maxium entropy input length (max_length) 2^35 bits
 *
 * Seed length (seedlen):
 * 440 for SHA-256
 * 888 for SHA-512
 *
 * Maximum personalization string length 2^35 bits
 * Maximum additional input length       2^35 bits
 * max_number_of_bits_per_request        2^19 bits
 *
 * Maximum number of requests between reseeds 2^48 (reseed_interval)
 */

// ==========================================================

/**
 * Get entropy input - wrapper around some OS provided RNG
 *
 * For now it will stay simplified, but formally it shall follow SP 800-90B / SP 800-90C
 *
 * (status, entropy_input) = Get_entropy_input (min_entropy, min_ length, max_length, prediction_resistance_request)
 */
static stasRet stas_HMAC_DRBG_get_entropy_input(uint8_t* buff_p, uint16_t len) {
    stasRet ret = FAILURE;

    if (buff_p) {
        FILE* fp = fopen(STAS_HMAC_DRBG_DEV_URAND_STR, "rb");

        if (fp) {
            if (fread(buff_p, sizeof(uint8_t), len, fp) == len) {
                ret = SUCCESS;
            }

            (void) fclose(fp);
        }
    }

    return ret;
}

// ==========================================================

/**
 * HMAC_DRGB Update function
 */
static stasRet stas_HMAC_DRBG_update(const uint8_t* const data_p, uint32_t data_len, HMACDRBGState* state_p) {
    stasRet ret = FAILURE;

    if (state_p == NULL) {
        return ret;
    }

    uint8_t* tmp_k = NULL;
    uint8_t* tmp_v = NULL;
    uint8_t* tmp_input_p = NULL;
    uint64_t tmp_len = 0U;

    if ((data_p == NULL) || (data_len == 0U)) {
        tmp_len = STAS_HMAC_DRBG_OUTLEN_BYTES + 1U;
    }
    else {
        tmp_len = STAS_HMAC_DRBG_OUTLEN_BYTES + 1U + data_len;
    }

    tmp_input_p = (uint8_t*) calloc(tmp_len, sizeof(uint8_t));

    if (tmp_input_p) {
        // step 1.
        (void) memcpy(tmp_input_p, state_p->V, STAS_HMAC_DRBG_OUTLEN_BYTES);
        tmp_input_p[STAS_HMAC_DRBG_OUTLEN_BYTES] = (uint8_t) 0x00;

        if ((data_p != NULL) && (data_len != 0U)) {
            (void) memcpy(&tmp_input_p[STAS_HMAC_DRBG_OUTLEN_BYTES + 1U], data_p, data_len);
        }

        tmp_k = stas_hmac_sha256(state_p->K, STAS_HMAC_DRBG_OUTLEN_BYTES, tmp_input_p, tmp_len);

        if (tmp_k == NULL) {
            stas_secure_zero(tmp_input_p, tmp_len);
            free(tmp_input_p);
            tmp_input_p = NULL;
            ret = FAILURE;
            return ret;
        }

        for (uint32_t i = 0U; i < STAS_SHA256_DGST_LEN_BYTES; i++) {
            state_p->K[i] = tmp_k[i];
        }

        stas_secure_zero(tmp_k, STAS_SHA256_DGST_LEN_BYTES);
        free(tmp_k);
        tmp_k = NULL;

        // step 2.
        tmp_v = stas_hmac_sha256(state_p->K, STAS_SHA256_DGST_LEN_BYTES, state_p->V, STAS_SHA256_DGST_LEN_BYTES);

        if (tmp_v == NULL) {
            stas_secure_zero(tmp_input_p, tmp_len);
            free(tmp_input_p);
            tmp_input_p = NULL;
            ret = FAILURE;
            return ret;
        }

        for (uint32_t i = 0U; i < STAS_SHA256_DGST_LEN_BYTES; i++) {
            state_p->V[i] = tmp_v[i];
        }

        stas_secure_zero(tmp_v, STAS_SHA256_DGST_LEN_BYTES);
        free(tmp_v);
        tmp_v = NULL;

        // step 3. - end or go further
        if ((data_p != NULL) && (data_len != 0U)) {
            // step 4.
            stas_secure_zero(tmp_input_p, tmp_len);
            (void) memcpy(tmp_input_p, state_p->V, STAS_HMAC_DRBG_OUTLEN_BYTES);
            tmp_input_p[STAS_HMAC_DRBG_OUTLEN_BYTES] = (uint8_t) 0x01;
            (void) memcpy(&tmp_input_p[STAS_HMAC_DRBG_OUTLEN_BYTES + 1U], data_p, data_len);

            tmp_k = stas_hmac_sha256(state_p->K, STAS_HMAC_DRBG_OUTLEN_BYTES, tmp_input_p, tmp_len);

            if (tmp_k == NULL) {
                stas_secure_zero(tmp_input_p, tmp_len);
                free(tmp_input_p);
                tmp_input_p = NULL;
                ret = FAILURE;
                return ret;
            }

            for (uint32_t i = 0U; i < STAS_SHA256_DGST_LEN_BYTES; i++) {
                state_p->K[i] = tmp_k[i];
            }

            stas_secure_zero(tmp_k, STAS_SHA256_DGST_LEN_BYTES);
            free(tmp_k);
            tmp_k = NULL;

            // step 5.
            tmp_v = stas_hmac_sha256(state_p->K, STAS_SHA256_DGST_LEN_BYTES, state_p->V, STAS_SHA256_DGST_LEN_BYTES);

            if (tmp_v == NULL) {
                stas_secure_zero(tmp_input_p, tmp_len);
                free(tmp_input_p);
                tmp_input_p = NULL;
                ret = FAILURE;
                return ret;
            }

            for (uint32_t i = 0U; i < STAS_SHA256_DGST_LEN_BYTES; i++) {
                state_p->V[i] = tmp_v[i];
            }

            stas_secure_zero(tmp_v, STAS_SHA256_DGST_LEN_BYTES);
            free(tmp_v);
            tmp_v = NULL;

            // step 6.
            ret = SUCCESS;
        }
        else {
            ret = SUCCESS;
        }

        stas_secure_zero(tmp_input_p, tmp_len);
        free(tmp_input_p);
        tmp_input_p = NULL;
    }

    return ret;
}

/**
 *
 * Instantiate_function (requested_instantiation_security_strength, prediction_resistance_flag, personalization_string)
 *
 * The instantiate function:
 * 1. Checks the validity of the input parameters,
 * 2. Determines the security strength for the DRBG instantiation,
 * 3. Obtains entropy input with entropy sufficient to support the security strength,
 * 4. Obtains the nonce (if required),
 * 5. Determines the initial internal state using the instantiate algorithm, and
 * 6. If an implementation supports multiple simultaneous instantiations of the same DRBG,
 *    a state_handle for the internal state is returned to the consuming application
 */
stasRet stas_HMAC_DRBG_instantiate(const uint8_t* const entropy_p, uint16_t entropy_len, const uint8_t* const nonce_p, uint16_t nonce_len,
                              const uint8_t* const personal_p, uint16_t personal_len, HMACDRBGState* state_p)
{
    stasRet ret = FAILURE;

    if ((entropy_p == NULL) || (entropy_len == 0U) || (nonce_p == NULL) || (nonce_len == 0U) || (state_p == NULL)) {
        ret = INVALID_ARG;
        return ret;
    }

    // step 1.
    uint32_t seed_material_len = 0U;
    uint8_t* seed_material_p = NULL;

    if ((personal_len > 0U) && (personal_p != NULL)) {
        seed_material_len = (entropy_len + nonce_len + personal_len) * sizeof(uint8_t);
        seed_material_p = (uint8_t*) calloc(seed_material_len, sizeof(uint8_t));

        if (seed_material_p) {
            (void) memcpy(seed_material_p, (uint8_t*) entropy_p, entropy_len * sizeof(uint8_t));
            (void) memcpy(&seed_material_p[entropy_len * sizeof(uint8_t)], nonce_p, nonce_len * sizeof(uint8_t));
            (void) memcpy(&seed_material_p[(entropy_len + nonce_len) * sizeof(uint8_t)], personal_p, personal_len * sizeof(uint8_t));
        }
        else {
            return ret;
        }
    }
    else {
        seed_material_len = entropy_len + nonce_len;
        seed_material_p = (uint8_t*) calloc(seed_material_len, sizeof(uint8_t));

        if (seed_material_p) {
            (void) memcpy(seed_material_p, entropy_p, entropy_len * sizeof(uint8_t));
            (void) memcpy(&seed_material_p[entropy_len * sizeof(uint8_t)], nonce_p, nonce_len * sizeof(uint8_t));
        }
        else {
            return ret;
        }
    }

    // step 2. & 3.
    for (uint32_t i = 0U; i < STAS_HMAC_DRBG_OUTLEN_BYTES; i++) {
        state_p->V[i] = 0x01;
        state_p->K[i] = 0x00;
    }

    /// step 4.
    ret = stas_HMAC_DRBG_update(seed_material_p, seed_material_len, state_p);

    // step 5.
    if (ret == SUCCESS) {
        state_p->reseed_ctr = 1U;
    }

    stas_secure_zero(seed_material_p, seed_material_len);
    free(seed_material_p);

    // step 6.
    return ret;
}

// ==========================================================

/**
 * Reseed_function (state_handle, prediction_resistance_request, additional_input)
 *
 * The reseed function:
 * 1. Checks the validity of the input parameters,
 * 2. Obtains entropy input from a randomness source that supports the security strength of the
 *    DRBG, and
 * 3. Using the reseed algorithm, combines the current working state with the new entropy
 *    input and any additional input to determine the new working state.
 */
static stasRet stas_HMAC_DRBG_reseed(const uint8_t* const entropy_p, uint16_t entropy_len, HMACDRBGState* state_p, const uint8_t* const additional_p, uint16_t additional_len) {
    stasRet ret = FAILURE;

    if ((entropy_p == NULL) || (entropy_len == 0U) || (state_p == NULL)) {
        ret = INVALID_ARG;
        return ret;
    }

    uint32_t seed_material_len = entropy_len + additional_len;
    uint8_t* seed_material_p = (uint8_t*) calloc(seed_material_len, sizeof(uint8_t));

    if (seed_material_p) {
        (void) memcpy(seed_material_p, entropy_p, entropy_len * sizeof(uint8_t));

        if ((additional_p != NULL) && (additional_len != 0U)) {
            (void) memcpy(&seed_material_p[entropy_len], additional_p, additional_len * sizeof(uint8_t));
        }

        ret = stas_HMAC_DRBG_update(seed_material_p, seed_material_len, state_p);

        stas_secure_zero(seed_material_p, seed_material_len);
        free(seed_material_p);
        seed_material_p = NULL;
    }

    return ret;
}

// ==========================================================

/**
 * Generate_function (state_handle, requested_number_of_bits, requested_security_strength, prediction_resistance_request, additional_input)
 *
 * The generate function:
 * 1. Checks the validity of the input parameters.
 * 2. Calls the reseed function to obtain sufficient entropy if the instantiation needs additional entropy because the end of the seedlife
 *    has been reached or prediction resistance is required; see Sections 9.3.2 and 9.3.3 for more information on reseeding at the end of the
 *    seedlife and on handling prediction resistance requests.
 * 3. Generates the requested pseudorandom bits using the generate algorithm.
 * 4. Updates the working state.
 * 5. Returns the requested pseudorandom bits to the consuming application.
 */
stasRet stas_HMAC_DRBG_generate(HMACDRBGState* state_p, uint8_t* bits_p, uint32_t bytes_len, const uint8_t* const additional_p, uint16_t additional_len) {
    stasRet ret = FAILURE;

    if ((state_p == NULL) || (bits_p == NULL) || (bytes_len == 0U) || (bytes_len > STAS_HMAC_DRBG_MAX_BYTES_PER_REQUEST)) {
        ret = INVALID_ARG;
        return ret;
    }

    // step 1.
    if (state_p->reseed_ctr > STAS_HMAC_DRBG_RESEED_INT) {
        uint16_t reseed_entropy_len = STAS_HMAC_DRBG_ENTROPY_LEN, reseed_add_len = STAS_HMAC_DRBG_ENTROPY_LEN;
        uint8_t* reseed_entropy_p = (uint8_t*) calloc(reseed_entropy_len, sizeof(uint8_t));

        if (reseed_entropy_p) {
            ret = stas_HMAC_DRBG_get_entropy_input(reseed_entropy_p, reseed_entropy_len);

            uint8_t* reseed_add_p = (uint8_t*) calloc(reseed_add_len, sizeof(uint8_t));

            if ((ret != SUCCESS) || (additional_p == NULL)) {
                free(reseed_entropy_p);
                ret = FAILURE;
                return ret;
            }

            ret = stas_HMAC_DRBG_get_entropy_input(reseed_add_p, reseed_add_len);

            if (ret == SUCCESS) {
                ret = stas_HMAC_DRBG_reseed(reseed_entropy_p, reseed_entropy_len, state_p, reseed_add_p, reseed_add_len);
            }

            stas_secure_zero(reseed_entropy_p, reseed_entropy_len);
            stas_secure_zero(reseed_add_p, reseed_add_len);
            free(reseed_entropy_p);
            free(reseed_add_p);

            if (ret != SUCCESS) {
                return ret;
            }
        }
        else {
            return ret;
        }
    }

    // step 2.
    if ((additional_p != NULL) && (additional_len != 0U)) {
        ret = stas_HMAC_DRBG_update(additional_p, additional_len, state_p);

        if (ret != SUCCESS) {
            return ret;
        }
    }

    // step 3.
    uint8_t* temp = (uint8_t*) calloc(bytes_len, sizeof(uint8_t));

    if (!temp) {
        return ret;
    }

    uint32_t bytes_ctr = 0U, copy_len = 0U;
    uint8_t* tmp_hmac = NULL;

    // step 4.
    while (bytes_ctr < bytes_len) {
        tmp_hmac = stas_hmac_sha256(state_p->K, STAS_HMAC_DRBG_OUTLEN_BYTES, state_p->V, STAS_HMAC_DRBG_OUTLEN_BYTES);

        if (tmp_hmac) {
            // step 4.1.
            for (uint32_t i = 0U; i < STAS_HMAC_DRBG_OUTLEN_BYTES; i++) {
                state_p->V[i] = tmp_hmac[i];
            }

            // step 4.2.
            copy_len = ((bytes_len - bytes_ctr) >= STAS_HMAC_DRBG_OUTLEN_BYTES) ? STAS_HMAC_DRBG_OUTLEN_BYTES : (bytes_len - bytes_ctr);
            (void) memcpy(&temp[bytes_ctr], tmp_hmac, copy_len);
            stas_secure_zero(tmp_hmac, STAS_HMAC_DRBG_OUTLEN_BYTES);
            free(tmp_hmac);
            tmp_hmac = NULL;

            bytes_ctr += copy_len;
        }
        else {
            stas_secure_zero(temp, bytes_len);
            free(temp);
            return ret;
        }
    }

    // step 6.
    ret = stas_HMAC_DRBG_update(additional_p, additional_len, state_p);
    state_p->reseed_ctr++;

    // step 7.
    (void) memcpy(bits_p, temp, bytes_len);

    stas_secure_zero(temp, bytes_len);
    free(temp);

    return ret;
}

// ==========================================================

/**
 * Uninstantiate_function (state_handle)
 *
 * The uninstantiate function:
 * 1. Checks the input parameter for validity, and
 * 2. Empties the internal state.
 */
stasRet stas_HMAC_DRBG_uninstantiate(HMACDRBGState* state_p) {
    stasRet ret = FAILURE;

    if (state_p) {
        state_p->reseed_ctr = 0U;
        stas_secure_zero(state_p->K, STAS_HMAC_DRBG_OUTLEN_BYTES);
        stas_secure_zero(state_p->V, STAS_HMAC_DRBG_OUTLEN_BYTES);
        ret = SUCCESS;
    }

    return ret;
}

// ==========================================================
/**
 * Wrapper for simple export use
 */
stasRet stas_HMAC_DRBG_easy_generate_once(uint8_t* output_p, uint32_t byte_len) {
    stasRet ret = FAILURE;

    if ((output_p == NULL) || (byte_len == 0U)) {
        return ret;
    }

    uint8_t entropy[STAS_HMAC_DRBG_ENTROPY_LEN];
    uint8_t nonce[STAS_HMAC_DRBG_ENTROPY_LEN];
    uint8_t personal[STAS_HMAC_DRBG_ENTROPY_LEN];

    ret = stas_HMAC_DRBG_get_entropy_input(entropy, STAS_HMAC_DRBG_ENTROPY_LEN);

    if (ret != SUCCESS) {
        return ret;
    }

    ret = stas_HMAC_DRBG_get_entropy_input(nonce, STAS_HMAC_DRBG_ENTROPY_LEN);

    if (ret != SUCCESS) {
        return ret;
    }

    ret = stas_HMAC_DRBG_get_entropy_input(personal, STAS_HMAC_DRBG_ENTROPY_LEN);

    if (ret != SUCCESS) {
        return ret;
    }

    HMACDRBGState state;
    ret = stas_HMAC_DRBG_instantiate(entropy, STAS_HMAC_DRBG_ENTROPY_LEN, nonce, STAS_HMAC_DRBG_ENTROPY_LEN, personal, STAS_HMAC_DRBG_ENTROPY_LEN, &state);

    if (ret != SUCCESS) {
        return ret;
    }

    uint8_t addition[STAS_HMAC_DRBG_ENTROPY_LEN];
    ret = stas_HMAC_DRBG_get_entropy_input(addition, STAS_HMAC_DRBG_ENTROPY_LEN);

    if (ret != SUCCESS) {
        return ret;
    }

    ret = stas_HMAC_DRBG_generate(&state, output_p, byte_len, addition, STAS_HMAC_DRBG_ENTROPY_LEN);

    ret = stas_HMAC_DRBG_uninstantiate(&state);

    stas_secure_zero(entropy, STAS_HMAC_DRBG_ENTROPY_LEN);
    stas_secure_zero(nonce, STAS_HMAC_DRBG_ENTROPY_LEN);
    stas_secure_zero(personal, STAS_HMAC_DRBG_ENTROPY_LEN);
    stas_secure_zero(addition, STAS_HMAC_DRBG_ENTROPY_LEN);

    return ret;
}

// ==========================================================

/**
 * test helpers
 */

static void HMAC_DRBG_test_personalization_string_32U(uint8_t* buff_p) {
    if (!buff_p) {
        return;
    }

    const uint8_t byte_array[32U] = {
        0x43,
        0x50,
        0x1b,
        0x96,
        0x1a,
        0x81,
        0xbc,
        0x44,
        0x58,
        0xfd,
        0x9d,
        0xc1,
        0x59,
        0x83,
        0xf4,
        0xab,
        0xa6,
        0xcd,
        0x9a,
        0x11,
        0x60,
        0x02,
        0x94,
        0xa2,
        0xbb,
        0x8e,
        0x05,
        0x18,
        0xd2,
        0xef,
        0x5a,
        0x6b,
    };

    (void) memcpy(buff_p, byte_array, 32U);
}

static void HMAC_DRBG_test_nonce_16U(uint8_t* buff_p) {
    if (!buff_p) {
        return;
    }

    const uint8_t byte_array[16U] = {
        0xc7,
        0xee,
        0x4e,
        0xa3,
        0xef,
        0xea,
        0x01,
        0xa2,
        0x2c,
        0xeb,
        0xa0,
        0x3f,
        0x86,
        0xe3,
        0x23,
        0xc8,
    };

    (void) memcpy(buff_p, byte_array, 16U);
}

static void HMAC_DRBG_test_additional1_32U(uint8_t* buff_p) {
    if (!buff_p) {
        return;
    }

    const uint8_t byte_array[32U] = {
        0x7d,
        0x14,
        0x6d,
        0x12,
        0x46,
        0x43,
        0xab,
        0x68,
        0x6e,
        0x9b,
        0xf2,
        0x18,
        0x7b,
        0x88,
        0x76,
        0x9f,
        0x24,
        0x43,
        0xd6,
        0xdc,
        0x16,
        0xfd,
        0xdf,
        0xe4,
        0x13,
        0xf9,
        0xb1,
        0x87,
        0xaa,
        0x2e,
        0x6b,
        0x8b,
    };

    (void) memcpy(buff_p, byte_array, 32U);
}

static void HMAC_DRBG_test_additional2_32U(uint8_t* buff_p) {
    if (!buff_p) {
        return;
    }

    const uint8_t byte_array[32U] = {
        0x6d,
        0xc7,
        0xb3,
        0x64,
        0xbd,
        0xc9,
        0x65,
        0x9e,
        0x92,
        0xb7,
        0xb9,
        0x35,
        0x43,
        0x25,
        0x19,
        0xbf,
        0x44,
        0x90,
        0x6f,
        0xc7,
        0x9c,
        0x3e,
        0x17,
        0x8e,
        0x68,
        0x8d,
        0x98,
        0xd7,
        0xf1,
        0xc7,
        0x8a,
        0x55,
    };

    (void) memcpy(buff_p, byte_array, 32U);
}


void hmac_drbg_test(void) {
    stasRet ret = FAILURE;

    uint8_t nonce[16U];
    HMAC_DRBG_test_nonce_16U(nonce);

    uint8_t entr[32U];
    ret = stas_HMAC_DRBG_get_entropy_input(entr, 32U);

    if (ret != SUCCESS) {
        printf("test failed at %d\n", __LINE__);
        return;
    }

    HMACDRBGState state = { 0 };

    uint8_t person[32U];

    HMAC_DRBG_test_personalization_string_32U(person);

    ret = stas_HMAC_DRBG_instantiate(entr, 32U, nonce, 16U, person, 32U, &state);

    if (ret != SUCCESS) {
        printf("test failed at %d\n", __LINE__);
        return;
    }
    else {
        printf("person:\n");
        for (uint16_t i = 0U; i < 32U; i++) {
            printf("%02x", person[i]);
        }
        printf("\ninstantiate\nkey:\n");
        for (uint16_t i = 0U; i < 32U; i++) {
            printf("%02x", state.K[i]);
        }
        printf("\nvalue:\n");
        for (uint16_t i = 0U; i < 32U; i++) {
            printf("%02x", state.V[i]);
        }
        printf("\n");
    }

    uint8_t output[128U];

    uint8_t add[32U];

    HMAC_DRBG_test_additional1_32U(add);

    ret = stas_HMAC_DRBG_generate(&state, output, 128U, add, 32U);

    if (ret != SUCCESS) {
        printf("test failed at %d\n", __LINE__);
        return;
    }
    else {
        printf("\nadd:\n");
        for(uint16_t i = 0U; i < 32U; i++) {
            printf("%02x", add[i]);
        }
        printf("\ngenerate 1\nkey:\n");
        for (uint16_t i = 0U; i < 32U; i++) {
            printf("%02x", state.K[i]);
        }
        printf("\nvalue:\n");
        for (uint16_t i = 0U; i < 32U; i++) {
            printf("%02x", state.V[i]);
        }
        printf("\noutput:\n");
        for (uint16_t i = 0U; i < 128U; i++) {
            printf("%02x", output[i]);
        }
        printf("\n");
    }

    stas_secure_zero(output, 128U);
    HMAC_DRBG_test_additional2_32U(add);
    ret = stas_HMAC_DRBG_generate(&state, output, 128U, add, 32U);

    if (ret != SUCCESS) {
        printf("test failed at %d\n", __LINE__);
        return;
    }
    else {
        printf("\nadd:\n");
        for(uint16_t i = 0U; i < 32U; i++) {
            printf("%02x", add[i]);
        }
        printf("\ngenerate 2\nkey:\n");
        for (uint16_t i = 0U; i < 32U; i++) {
            printf("%02x", state.K[i]);
        }
        printf("\nvalue:\n");
        for (uint16_t i = 0U; i < 32U; i++) {
            printf("%02x", state.V[i]);
        }
        printf("\noutput:\n");
        for (uint16_t i = 0U; i < 128U; i++) {
            printf("%02x", output[i]);
        }
        printf("\n");
    }
}
