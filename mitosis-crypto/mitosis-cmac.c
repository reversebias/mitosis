#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "mitosis-cmac.h"

static inline void shiftleft(const uint8_t* in, uint8_t* out)
{
    uint32_t overflow = 0;
    for (int i = 15; i >= 0; --i)
    {
        out[i] = in[i] << 1;
        out[i] |= overflow;
        overflow = (in[i] & 0x80) ? 1 : 0;
    }
}

static inline void xor128(const uint8_t* left, const uint8_t* right, uint8_t* out)
{
    for (int i = 0; i < 4; ++i)
    {
        ((uint32_t*) out)[i] = ((const uint32_t*) left)[i] ^ ((const uint32_t*) right)[i];
    }
}

static inline void xor(const uint8_t* left, const uint8_t* right, size_t len, uint8_t* out)
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

bool mitosis_cmac_init(mitosis_cmac_context_t* context, const uint8_t* key, size_t key_len)
{
    if (key_len < sizeof(context->ecb.key))
    {
        // Left-pad key with zeroes.
        uint32_t delta = sizeof(context->ecb.key) - key_len;
        uint32_t idx = 0;
        for (; idx < delta; ++idx)
        {
            context->ecb.key[idx] = 0;
        }
        for (uint32_t key_idx = 0; idx < sizeof(context->ecb.key); ++idx, ++key_idx)
        {
            context->ecb.key[idx] = key[key_idx];
        }
    }
    else
    {
        // If key length is greater than AES-128 key length, truncate.
        memcpy(context->ecb.key, key, sizeof(context->ecb.key));
    }
    memset(context->ecb.plaintext, 0, sizeof(context->ecb.plaintext));
    context->multiblock = false;
    context->plaintext_index = 0;

    if (!mitosis_aes_ecb_encrypt(&context->ecb))
    {
        return false;
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

    return true;
}

bool inline mitosis_cmac_hash(mitosis_cmac_context_t* context, const uint8_t* data, size_t data_len)
{
    do
    {
        int available_space = AES_BLOCK_SIZE - context->plaintext_index;
        // copy data into plaintext
        if (data_len <= available_space)
        {
            // Note: If this is unaligned, ARM will crash.
            memcpy(context->ecb.plaintext + context->plaintext_index, data, data_len);
            context->plaintext_index += data_len;
            data_len = 0;
        }
        else
        {
            // Note: If this is unaligned, ARM will crash.
            memcpy(context->ecb.plaintext + context->plaintext_index, data, available_space);
            context->plaintext_index += available_space;
            data += available_space;
            data_len -= available_space;
        }

        // if plaintext is full and there's more data left to copy, process plaintext
        if (context->plaintext_index == AES_BLOCK_SIZE && data_len > 0)
        {
            // carry forward previous result, if present
            if (context->multiblock)
            {
                xor128(context->ecb.ciphertext, context->ecb.plaintext, context->ecb.plaintext);
            }
            // compute hash
            if (!mitosis_aes_ecb_encrypt(&context->ecb))
            {
                return false;
            }
            context->multiblock = true;
            context->plaintext_index = 0;
        }
    }
    while (data_len > 0);

    return true;
}

bool inline mitosis_cmac_complete(mitosis_cmac_context_t* context, uint8_t* output)
{
    // Prepare the last block of data in the plaintext.
    if (context->plaintext_index == AES_BLOCK_SIZE)
    {
        xor128(context->ecb.plaintext, context->key1, context->ecb.plaintext);
    }
    else
    {
        // XOR the remaining data with K2.
        xor(context->ecb.plaintext, context->key2, context->plaintext_index, context->ecb.plaintext);
        // XOR K2 with the first byte of padding.
        context->ecb.plaintext[context->plaintext_index] = 0x80 ^ context->key2[context->plaintext_index];
        // If there's more data, copy K2 into input.
        if (context->plaintext_index < 15)
        {
            // Note: If this is unaligned, ARM will crash.
            memcpy(
                context->ecb.plaintext + context->plaintext_index + 1,
                context->key2 + context->plaintext_index + 1,
                sizeof(context->ecb.plaintext) - context->plaintext_index - 1);
        }
    }

    // If previous blocks were processed, XOR them into the last block.
    if (context->multiblock)
    {
        xor128(context->ecb.plaintext, context->ecb.ciphertext, context->ecb.plaintext);
    }

    if (!mitosis_aes_ecb_encrypt(&context->ecb))
    {
        return false;
    }

    context->multiblock = false;
    context->plaintext_index = 0;
    memcpy(output, context->ecb.ciphertext, sizeof(context->ecb.ciphertext));
    return true;
}

bool mitosis_cmac_compute(mitosis_cmac_context_t* context, const uint8_t* data, size_t datalen, uint8_t* output)
{
    if (!mitosis_cmac_hash(context, data, datalen))
    {
        return false;
    }
    if (!mitosis_cmac_complete(context, output))
    {
        return false;
    }

    return true;
}
