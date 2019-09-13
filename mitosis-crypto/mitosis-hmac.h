/*
Interface for HMAC-SHA256 for Mitosis keyboard
*/
#include "sha256.h"
#define SHA256_BLOCK_SIZE 64

#define MITOSIS_HMAC_OUTPUT_SIZE 32

typedef struct _mitosis_hmac_context_t {
    sha256_context_t sha256_context;
    uint8_t inner_key[SHA256_BLOCK_SIZE];
    uint8_t outer_key[SHA256_BLOCK_SIZE];
    uint32_t need_reset : 1;
} mitosis_hmac_context_t;

bool mitosis_hmac_init(mitosis_hmac_context_t* state, const uint8_t* key, size_t len);

bool mitosis_hmac_hash(mitosis_hmac_context_t* state, const uint8_t* data, size_t len);

bool mitosis_hmac_complete(mitosis_hmac_context_t* state, uint8_t* hash);
