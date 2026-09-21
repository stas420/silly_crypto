#ifndef STAS_HMAC_H__
#define STAS_HMAC_H__

#include <stdint.h>

/**
 * @brief HMAC implementation basing on SHA-256 algo - as per FIPS 198-1, Section 4.
 *
 * @param[in] key_p     pointer to the hash key buffer
 * @param[in] key_len   length of the buffer pointed to by *key_p*
 * @param[in] data_p    pointer to the data buffer which shall undergo hashing
 * @param[in] data_len  length of the buffer pointed to by *data_p*
 *
 * @return uint8_t*     on success: pointer to NEWLY HEAP-ALLOCATED MEMORY containing the hash value of length STAS_SHA256_DGST_LEN_BYTES - this must be later freed by the user
 *                      on failure: NULL pointer
 */
uint8_t* stas_hmac_sha256(const uint8_t* const key_p, uint32_t key_len, const uint8_t* const data_p, uint32_t data_len);

#endif // STAS_HMAC_H__
