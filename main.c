#include <stdio.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "stas_ifc_keygen.h"

uint8_t* readInputFile(const char* const path, uint64_t* out_file_len_p);
void testHMAC(void);

int main(int argc, char** argv) {

    uint8_t p_arr[STAS_IFC_KEYGEN_RSA_2048_KEYLEN / 2U / 8U];
    uint8_t q_arr[STAS_IFC_KEYGEN_RSA_2048_KEYLEN / 2U / 8U];
    size_t p_len = 0U, q_len = 0U;

    (void) stas_IFC_keygen_random_probable_primes(p_arr, &p_len, q_arr, &q_len, STAS_IFC_KEYGEN_RSA_2048_KEYLEN, STAS_IFC_KEYGEN_DEFAULT_PUBLIC_EXP);

    printf("P arr - size %lu:\n", p_len);
    for (uint32_t i = 0; i < p_len; i++) {
        printf("%02x ", p_arr[i]);
    }
    printf("\n");


    printf("Q arr - size %lu:\n", q_len);
    for (uint32_t i = 0; i < q_len; i++) {
        printf("%02x ", q_arr[i]);
    }
    printf("\n");

    return 0;
}

/**
 * Read input file as binary and puts it into a byte array
 *
 * @param path path to file to be read
 * @return pointer to HEAP ALLOCATED MEMORY, must be freed after use
 */
uint8_t* readInputFile(const char* const path, uint64_t* out_file_len_p) {
    struct stat s;

    if (stat(path, &s) == 0) {
        if (!(s.st_mode & S_IFREG)) {
            return NULL;
        }
    }
    else {
        return NULL;
    }

    FILE* file_p = fopen(path, "rb");
    uint8_t* buffer_p = NULL;

    if (file_p) {
        if (fseek(file_p, 0, SEEK_END) == 0) {
            (*out_file_len_p) = (uint64_t) ftell(file_p);
            rewind(file_p);

            buffer_p = (uint8_t*) malloc((*out_file_len_p) * sizeof(uint8_t));

            if (buffer_p) {
                (void) fread(buffer_p, 1, (*out_file_len_p), file_p);
            }
        }

        fclose(file_p);
    }

    return buffer_p;
}
