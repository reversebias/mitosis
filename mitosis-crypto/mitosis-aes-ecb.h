/*
    This file provides an alternate interface to the underlying AES engine.
    The point is to reduce the number of calls to memcpy().
*/

#ifndef _MITOSIS_AES_ECB
#define _MITOSIS_AES_ECB

#define AES_BLOCK_SIZE 16

typedef struct _mitosis_aes_ecb_context_t {
    uint8_t key[AES_BLOCK_SIZE];
    uint8_t plaintext[AES_BLOCK_SIZE];
    uint8_t ciphertext[AES_BLOCK_SIZE];
} mitosis_aes_ecb_context_t;

bool mitosis_aes_ecb_init(mitosis_aes_ecb_context_t* state);

bool mitosis_aes_ecb_encrypt(mitosis_aes_ecb_context_t* state);

#endif
