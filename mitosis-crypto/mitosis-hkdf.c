
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <mitosis-hmac.h>
#include "mitosis-hkdf.h"

bool
mitosis_hkdf_extract(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt, size_t salt_len, uint8_t* prk) {
    MITOSIS_HMAC_STATE state;
    bool result = true;
    result = mitosis_hmac_init(&state, salt, salt_len);
    if(!result) {
        return result;
    }
    result = mitosis_hmac_hash(&state, ikm, ikm_len);
    if(!result) {
        return result;
    }
    result = mitosis_hmac_complete(&state, prk);
    return result;
}

bool
mitosis_hkdf_expand(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) {
    MITOSIS_HMAC_STATE state;
    uint8_t scratch[MITOSIS_HMAC_OUTPUT_SIZE];
    bool result = true;
    uint8_t iterations;
    uint16_t offset = 0;

    if(okm_len > 255 * MITOSIS_HMAC_OUTPUT_SIZE) {
        return false;
    }

    if(okm_len % MITOSIS_HMAC_OUTPUT_SIZE) {
        iterations = (uint8_t)(okm_len / MITOSIS_HMAC_OUTPUT_SIZE) + 1;
    } else {
        iterations = (uint8_t)(okm_len / MITOSIS_HMAC_OUTPUT_SIZE);
    }

    result = mitosis_hmac_init(&state, prk, prk_len);
    if(!result) {
        return result;
    }

    for(uint8_t i = 1; i <= iterations && i > 0; ++i) {
        if(i > 1) {
            result = mitosis_hmac_hash(&state, scratch, sizeof(scratch));
            if(!result) {
                return result;
            }
        }

        result = mitosis_hmac_hash(&state, info, info_len);
        if(!result) {
            return result;
        }

        result = mitosis_hmac_hash(&state, &i, 1);
        if(!result) {
            return result;
        }

        result = mitosis_hmac_complete(&state, scratch);
        if(!result) {
            return result;
        }

        if(okm_len > sizeof(scratch)) {
            memcpy(okm + offset, scratch, sizeof(scratch));
            okm_len -= sizeof(scratch);
            offset += sizeof(scratch);
        } else {
            memcpy(okm + offset, scratch, okm_len);
        }
    }
    return result;
}
