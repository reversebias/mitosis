/*
Interface for HMAC-SHA256 for Mitosis keyboard
*/

typedef struct _MITOSIS_HMAC_STATE {
    uint8_t need_reset : 1;
    uint8_t[SHA256_BLOCK_SIZE] inner_key;
    uint8_t[SHA256_BLOCK_SIZE] outer_key;
    sha256_context_t hash;
} MITOSIS_HMAC_STATE;

#define MITOSIS_HMAC_OUTPUT_SIZE 32

bool mitosis_hmac_init(MITOSIS_HMAC_STATE* state, const uint8_t* key, size_t len);

bool mitosis_hmac_hash(MITOSIS_HMAC_STATE* state, const uint8_t* data, size_t len);

bool mitosis_hmac_complete(MITOSIS_HMAC_STATE* state, uint8_t* hash);
