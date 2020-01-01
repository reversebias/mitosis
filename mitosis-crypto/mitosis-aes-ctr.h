/*
Interface for AES in CTR mode for mitosis
*/
#include "mitosis-aes-ecb.h"

typedef struct _mitosis_aes_ctr_context_t {
    uint8_t key[AES_BLOCK_SIZE];
    union {
        struct {
            uint8_t nonce[AES_BLOCK_SIZE - sizeof(uint32_t)];
            uint32_t counter;
        } iv;
        uint8_t iv_bytes[AES_BLOCK_SIZE];
    };
    uint8_t scratch[AES_BLOCK_SIZE];
} mitosis_aes_ctr_context_t;

_Static_assert(sizeof(mitosis_aes_ctr_context_t) == sizeof(mitosis_aes_ecb_context_t));

typedef union _mitosis_encrypt_context_t {
    mitosis_aes_ecb_context_t ecb;
    mitosis_aes_ctr_context_t ctr;
} mitosis_encrypt_context_t;

/*
Key and nonce are 16 bytes for consistency.
*/
bool mitosis_aes_ctr_init(const uint8_t* key, const uint8_t* nonce, mitosis_encrypt_context_t* context);

bool mitosis_aes_ctr_encrypt(mitosis_encrypt_context_t* context, uint32_t datalen, const uint8_t* plaintext, uint8_t* ciphertext);

#define mitosis_aes_ctr_decrypt(context, datalen, ciphertext, plaintext) mitosis_aes_ctr_encrypt(context, datalen, ciphertext, plaintext)
