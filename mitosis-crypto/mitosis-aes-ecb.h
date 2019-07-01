/*
    This file provides an alternate interface to the underlying AES engine.
    The point is to reduce the number of calls to memcpy().
*/

#define AES_BLOCK_SIZE 16

typedef struct _mitosis_aes_ecb_state {
    uint8_t key[AES_BLOCK_SIZE];
    uint8_t plaintext[AES_BLOCK_SIZE];
    uint8_t ciphertext[AES_BLOCK_SIZE];
} MITOSIS_AES_ECB_STATE;

bool mitosis_aes_ecb_init(MITOSIS_AES_ECB_STATE* state);

bool mitosis_aes_ecb_encrypt(MITOSIS_AES_ECB_STATE* state);
