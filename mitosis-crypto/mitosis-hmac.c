#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "mitosis-hmac.h"
#include <stdio.h>

#define INNER_PAD 0x36
#define OUTER_PAD 0x5c
#define INNER_PAD_32 (uint32_t)0x36363636
#define OUTER_PAD_32 (uint32_t)0x5c5c5c5c



bool
mitosis_hmac_init(mitosis_hmac_context_t* state, const uint8_t* key, size_t len)
{
    if (state == 0 || key == 0)
    {
        return false;
    }

    if (len > SHA256_BLOCK_SIZE)
    {
        uint8_t newKey[MITOSIS_HMAC_OUTPUT_SIZE] = { 0 };
        sha256_init(&(state->sha256_context));
        sha256_update(&(state->sha256_context), key, len);
        sha256_final(&(state->sha256_context), newKey);
        key = newKey;
        len = MITOSIS_HMAC_OUTPUT_SIZE;
    }

    // create inner and outer key from key material.
    uint32_t idx = 0;
    for (; len - idx > 4; idx += 4)
    {
        // This does a "fast" XOR by doing 32-bits at a time.
        *(uint32_t*)(state->inner_key + idx) = *(uint32_t*)(key + idx) ^ INNER_PAD_32;
        *(uint32_t*)(state->outer_key + idx) = *(uint32_t*)(key + idx) ^ OUTER_PAD_32;
    }
    for (; len - idx > 0; ++idx)
    {
        // Fallback to "slow" XOR for the rest of the key material.
        state->inner_key[idx] = key[idx] ^ INNER_PAD;
        state->outer_key[idx] = key[idx] ^ OUTER_PAD;
    }
    for (; (idx & 0x3) && idx < sizeof(state->inner_key); ++idx)
    {
        // "Slow" copy to the next 4-byte boundary.
        state->inner_key[idx] = INNER_PAD;
        state->outer_key[idx] = OUTER_PAD;
    }
    for (; idx < sizeof(state->inner_key); idx += 4)
    {
        // "Fast" copy the rest of the key material.
        *(uint32_t*)(state->inner_key + idx) = INNER_PAD_32;
        *(uint32_t*)(state->outer_key + idx) = OUTER_PAD_32;
    }

    sha256_init(&(state->sha256_context));

    sha256_update(&(state->sha256_context), state->inner_key, sizeof(state->inner_key));

    return true;
}

bool
mitosis_hmac_hash(mitosis_hmac_context_t* state, const uint8_t* data, size_t len)
{
    if (state == 0 || data == 0)
    {
        return false;
    }
    if (state->need_reset)
    {
        sha256_init(&(state->sha256_context));
        sha256_update(&(state->sha256_context), state->inner_key, sizeof(state->inner_key));
        state->need_reset = 0;
    }
    return sha256_update(&(state->sha256_context), data, len) == NRF_SUCCESS;
}

bool
mitosis_hmac_complete(mitosis_hmac_context_t* state, uint8_t* hash) {
    if (state == 0 || hash == 0)
    {
        return false;
    }
    uint8_t first_hash[MITOSIS_HMAC_OUTPUT_SIZE];
    state->need_reset = 1;
    sha256_final(&(state->sha256_context), first_hash);
    // Re-use the hash object to compute the 2nd hash pass.
    sha256_init(&(state->sha256_context));
    sha256_update(&(state->sha256_context), state->outer_key, sizeof(state->outer_key));
    sha256_update(&(state->sha256_context), first_hash, sizeof(first_hash));
    return sha256_final(&(state->sha256_context), hash) == NRF_SUCCESS;
}
