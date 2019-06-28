#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "mitosis-hmac.h"
#include <stdio.h>

#define SHA256_OUTPUT_SIZE 32
#define INNER_PAD_32 (uint32_t)0x36363636
#define OUTER_PAD_32 (uint32_t)0x5c5c5c5c



bool
mitosis_hmac_init(MITOSIS_HMAC_STATE* state, const uint8_t* key, size_t len) {
    if(state == 0 || key == 0) {
        return false;
    }

    // create inner and outer key from key material
    for(int i = 0; i < sizeof(state->inner_key); i += 4) {
        *(uint32_t*)(state->inner_key + i) = INNER_PAD_32;
    }

    for(int i = 0; i < sizeof(state->outer_key); i += 4) {
        *(uint32_t*)(state->outer_key + i) = OUTER_PAD_32;
    }

    if(len > SHA256_BLOCK_SIZE) {
        uint8_t newKey[SHA256_OUTPUT_SIZE] = { 0 };
        sha256_init(&(state->hash));
        sha256_update(&(state->hash), key, len);
        sha256_final(&(state->hash), newKey);
        key = newKey;
        len = SHA256_OUTPUT_SIZE;
    }

    uint32_t idx = 0;
    for(; len - idx > 4; idx += 4) {
        *(uint32_t*)(state->inner_key + idx) ^= *(uint32_t*)(key + idx);
        *(uint32_t*)(state->outer_key + idx) ^= *(uint32_t*)(key + idx);
    }
    for(; len - idx > 0; ++idx) {
        state->inner_key[idx] ^= key[idx];
        state->outer_key[idx] ^= key[idx];
    }

    sha256_init(&(state->hash));

    sha256_update(&(state->hash), state->inner_key, sizeof(state->inner_key));

    return true;
}

bool
mitosis_hmac_hash(MITOSIS_HMAC_STATE* state, const uint8_t* data, size_t len) {
    if(state == 0 || data == 0) {
        return false;
    }
    if(state->need_reset) {
        sha256_init(&(state->hash));
        sha256_update(&(state->hash), state->inner_key, sizeof(state->inner_key));
        state->need_reset = 0;
    }
    return sha256_update(&(state->hash), data, len) == NRF_SUCCESS;
}

bool
mitosis_hmac_complete(MITOSIS_HMAC_STATE* state, uint8_t* hash) {
    if(state == 0 || hash == 0) {
        return false;
    }
    uint8_t first_hash[SHA256_OUTPUT_SIZE];
    state->need_reset = 1;
    sha256_final(&(state->hash), first_hash);
    // Re-use the hash object to compute the 2nd hash pass.
    sha256_init(&(state->hash));
    sha256_update(&(state->hash), state->outer_key, sizeof(state->outer_key));
    sha256_update(&(state->hash), first_hash, sizeof(first_hash));
    return sha256_final(&(state->hash), hash) == NRF_SUCCESS;
}
