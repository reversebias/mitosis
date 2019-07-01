/*
Interface for AES in CTR mode for mitosis
*/
#include "mitosis-aes-ecb.h"

typedef struct _mitosis_aes_ctr_state {
    uint8_t key[AES_BLOCK_SIZE];
    union {
        struct {
            uint8_t nonce[12];
            uint32_t counter;
        } iv;
        uint8_t iv_bytes[AES_BLOCK_SIZE];
    };
    uint8_t scratch[AES_BLOCK_SIZE];
} MITOSIS_AES_CTR_STATE;

_Static_assert(sizeof(MITOSIS_AES_CTR_STATE) == sizeof(MITOSIS_AES_ECB_STATE));

typedef union _mitosis_encrypt_context {
    MITOSIS_AES_ECB_STATE ecb;
    MITOSIS_AES_CTR_STATE ctr;
} MITOSIS_ENCRYPT_CONTEXT;

/*
Key and nonce are 16 bytes for consistency.
*/
bool mitosis_aes_ctr_init(const uint8_t* key, const uint8_t* nonce, MITOSIS_ENCRYPT_CONTEXT* context);

bool mitosis_aes_ctr_encrypt(MITOSIS_ENCRYPT_CONTEXT* context, uint32_t datalen, const uint8_t* plaintext, uint8_t* ciphertext);

bool mitosis_aes_ctr_decrypt(MITOSIS_ENCRYPT_CONTEXT* context, uint32_t datalen, const uint8_t* ciphertext, uint8_t* plaintext);
