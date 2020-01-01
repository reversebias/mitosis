#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "mitosis-aes-ctr.h"

bool mitosis_aes_ctr_init(const uint8_t* key, const uint8_t* nonce, mitosis_encrypt_context_t* context)
{
    memset(context, 0, sizeof(*context));
    memcpy(context->ctr.key, key, sizeof(context->ctr.key));
    memcpy(context->ctr.iv_bytes, nonce, sizeof(context->ctr.iv_bytes));
    return mitosis_aes_ecb_init(&context->ecb);
}

static inline
void xor(const uint8_t* left, const uint8_t* right, size_t len, uint8_t* out)
{
    int idx = 0;
    for (; len >= 4; idx += 4, len -= 4)
    {
        *((uint32_t*) &out[idx]) = *((uint32_t*) &left[idx]) ^ *((uint32_t*) &right[idx]);
    }
    if (len >= 2)
    {
        *((uint16_t*) &out[idx]) = *((uint16_t*) &left[idx]) ^ *((uint16_t*) &right[idx]);
        idx += 2;
        len -= 2;
    }
    if (len > 0)
    {
        out[idx] = left[idx] ^ right[idx];
    }
}

bool mitosis_aes_ctr_encrypt(mitosis_encrypt_context_t* context, uint32_t datalen, const uint8_t* plaintext, uint8_t* ciphertext)
{
    if (datalen > AES_BLOCK_SIZE)
    {
        return false;
    }

    if (!mitosis_aes_ecb_encrypt(&context->ecb))
    {
        return false;
    }
    xor(plaintext, context->ctr.scratch, datalen, ciphertext);

    return true;
}
