#include "stas_common.h"

#include <stdio.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void stas_secure_zero(void* data, uint64_t len) {
    volatile uint8_t* p = (volatile uint8_t*) data;

    while (len > 0) {
        *p = 0U;
        p++;
        len--;
    }
}

/**
 * Read input file as binary and puts it into a byte array
 *
 * @param path              path to file to be read
 * @param out_file_len_p    number of bytes written, i.e. length of the loaded file in bytes
 * @return                  on success: pointer to HEAP ALLOCATED MEMORY, must be freed after use / on failure: NULL
 */
uint8_t* stas_read_input_file(const char* const path, uint64_t* out_file_len_p) {
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
