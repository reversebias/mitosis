
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <mitosis-cmac.h>
#include "mitosis-ckdf.h"

bool mitosis_ckdf_extract(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt, size_t salt_len, uint8_t* prk)
{
    mitosis_cmac_context_t state;

    if (!mitosis_cmac_init(&state, salt, salt_len))
    {
        return false;
    }
    return mitosis_cmac_compute(&state, ikm, ikm_len, prk);
}

bool
mitosis_ckdf_expand(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len)
{
    mitosis_cmac_context_t state;
    uint8_t scratch[AES_BLOCK_SIZE];
    uint8_t iterations;
    uint16_t offset = 0;

    if (okm_len > 255 * AES_BLOCK_SIZE)
    {
        return false;
    }

    if (okm_len % AES_BLOCK_SIZE)
    {
        iterations = (uint8_t)(okm_len / AES_BLOCK_SIZE) + 1;
    }
    else
    {
        iterations = (uint8_t)(okm_len / AES_BLOCK_SIZE);
    }

    // i starts at 1 so it can be used to save the memory needed for a separate
    // block counter.
    for (uint8_t i = 1; i <= iterations && i > 0; ++i)
    {
        if (!mitosis_cmac_init(&state, prk, prk_len))
        {
            return false;
        }

        if (i > 1)
        {
            if (!mitosis_cmac_hash(&state, scratch, sizeof(scratch)))
            {
                return false;
            }
        }

        if (!mitosis_cmac_hash(&state, info, info_len))
        {
            return false;
        }

        if (!mitosis_cmac_hash(&state, &i, 1))
        {
            return false;
        }

        if (!mitosis_cmac_complete(&state, scratch))
        {
            return false;
        }

        if (okm_len > sizeof(scratch))
        {
            memcpy(okm + offset, scratch, sizeof(scratch));
            okm_len -= sizeof(scratch);
            offset += sizeof(scratch);
        }
        else
        {
            memcpy(okm + offset, scratch, okm_len);
        }
    }
    return true;
}
