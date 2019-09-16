#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "mitosis-cmac.h"

static void shiftleft(const uint8_t* in, uint8_t* out)
{
    uint32_t overflow = 0;
    for (int i = 15; i >= 0; --i)
    {
        out[i] = in[i] << 1;
        out[i] |= overflow;
        overflow = (in[i] & 0x80) ? 1 : 0;
    }
}

static void xor128(const uint8_t* left, const uint8_t* right, uint8_t* out)
{
    for (int i = 0; i < 4; ++i)
    {
        ((uint32_t*) out)[i] = ((const uint32_t*) left)[i] ^ ((const uint32_t*) right)[i];
    }
}

static void xor(const uint8_t* left, const uint8_t* right, size_t len, uint8_t* out)
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

bool mitosis_cmac_init(mitosis_cmac_context_t* context, uint8_t* key)
{
    bool result = true;

    memcpy(context->ecb.key, key, sizeof(context->ecb.key));
    memset(context->ecb.plaintext, 0, sizeof(context->ecb.plaintext));

    result = mitosis_aes_ecb_encrypt(&context->ecb);
    if (!result)
    {
        return result;
    }

    // Left-shift the output to generate K1.
    shiftleft(context->ecb.ciphertext, context->key1);

    // If MSB is 1, XOR the last byte of K1.
    if (context->ecb.ciphertext[0] & 0x80)
    {
        context->key1[15] ^= 0x87;
    }

    // Left-shift K1 to generate K2.
    shiftleft(context->key1, context->key2);

    // If MSB is 1, XOR the last byte of K2.
    if (context->key1[0] & 0x80)
    {
        context->key2[15] ^= 0x87;
    }

    return result;
}

bool mitosis_cmac_compute(mitosis_cmac_context_t* context, uint8_t* data, size_t datalen, uint8_t* output)
{
    bool result = true;
    int iterations = (int) (datalen / AES_BLOCK_SIZE);
    bool complete_last_block = true;

    if (datalen % AES_BLOCK_SIZE)
    {
        ++iterations;
        complete_last_block = false;
    }

    if (iterations == 0)
    {
        iterations = 1;
        complete_last_block = false;
    }

    for (int i = 1; i <= iterations - 1; ++i, data += AES_BLOCK_SIZE, datalen -= AES_BLOCK_SIZE)
    {
        if (i == 1)
        {
            memcpy(context->ecb.plaintext, data, sizeof(context->ecb.plaintext));
        }
        else
        {
            xor128(context->ecb.ciphertext, data, context->ecb.plaintext);
        }

        result = mitosis_aes_ecb_encrypt(&context->ecb);
        if (!result)
        {
            return result;
        }
    }

    // Prepare the last block of data in the plaintext.
    if (complete_last_block)
    {
        xor128(data, context->key1, context->ecb.plaintext);
    }
    else
    {
        // XOR the remaining data with K2.
        xor(data, context->key2, datalen, context->ecb.plaintext);
        // XOR K2 with the first byte of padding.
        context->ecb.plaintext[datalen] = 0x80 ^ context->key2[datalen];
        // If there's more data, copy K2 into input.
        if (datalen < 15)
        {
            memcpy(
                context->ecb.plaintext + datalen + 1,
                context->key2 + datalen + 1,
                sizeof(context->ecb.plaintext) - datalen - 1);
        }
    }

    // If previous blocks were processed, XOR them into the last block.
    if (iterations > 1)
    {
        xor128(context->ecb.plaintext, context->ecb.ciphertext, context->ecb.plaintext);
    }

    result = mitosis_aes_ecb_encrypt(&context->ecb);
    if (!result)
    {
        return result;
    }

    memcpy(output, context->ecb.ciphertext, sizeof(context->ecb.ciphertext));

    return result;
}
