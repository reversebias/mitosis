#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "mitosis-aes-ctr.h"

bool mitosis_aes_ctr_init(const uint8_t* key, const uint8_t* nonce, mitosis_encrypt_context_t* context) {
    memset(context, 0, sizeof(*context));
    memcpy(context->ctr.key, key, sizeof(context->ctr.key));
    memcpy(context->ctr.iv_bytes, nonce, sizeof(context->ctr.iv_bytes));
    return mitosis_aes_ecb_init(&context->ecb);
}

bool mitosis_aes_ctr_encrypt(mitosis_encrypt_context_t* context, uint32_t datalen, const uint8_t* plaintext, uint8_t* ciphertext) {
    if(datalen > AES_BLOCK_SIZE) {
        return false;
    }

    bool result;
    result = mitosis_aes_ecb_encrypt(&context->ecb);
    if(!result) {
        return result;
    }
    for(int idx = 0; idx < datalen; ++idx) {
        ciphertext[idx] = plaintext[idx] ^ context->ctr.scratch[idx];
    }
    return result;
}

bool mitosis_aes_ctr_decrypt(mitosis_encrypt_context_t* context, uint32_t datalen, const uint8_t* ciphertext, uint8_t* plaintext) {
    return mitosis_aes_ctr_encrypt(context, datalen, ciphertext, plaintext);
}
