/*
Interface for HMAC-SHA256 for Mitosis keyboard
*/
#include "sha256.h"
#define SHA256_BLOCK_SIZE 64

#define MITOSIS_HMAC_OUTPUT_SIZE 32

typedef struct _MITOSIS_HMAC_STATE {
    uint8_t need_reset : 1;
    uint8_t inner_key[SHA256_BLOCK_SIZE] ;
    uint8_t outer_key[SHA256_BLOCK_SIZE];
    sha256_context_t hash;
} MITOSIS_HMAC_STATE;

bool mitosis_hmac_init(MITOSIS_HMAC_STATE* state, const uint8_t* key, size_t len);

bool mitosis_hmac_hash(MITOSIS_HMAC_STATE* state, const uint8_t* data, size_t len);

bool mitosis_hmac_complete(MITOSIS_HMAC_STATE* state, uint8_t* hash);
