/*
    Implementation of CMAC using AES for Mitosis.
*/

#include "mitosis-aes-ecb.h"

#define MITOSIS_CMAC_OUTPUT_SIZE AES_BLOCK_SIZE

typedef struct _mitosis_cmac_context_t {
    uint8_t key1[AES_BLOCK_SIZE];
    uint8_t key2[AES_BLOCK_SIZE];
    mitosis_aes_ecb_context_t ecb;
    uint32_t multiblock : 1;
    uint32_t plaintext_index : 5;
} mitosis_cmac_context_t;

bool mitosis_cmac_init(mitosis_cmac_context_t* context, const uint8_t* key, size_t key_len);

bool mitosis_cmac_hash(mitosis_cmac_context_t* context, const uint8_t* data, size_t data_len);

bool mitosis_cmac_complete(mitosis_cmac_context_t* context, uint8_t* output);

// If all data is ready in a contiguous buffer, call this.
bool mitosis_cmac_compute(mitosis_cmac_context_t* context, const uint8_t* data, size_t datalen, uint8_t* output);
