#include <mitosis-hmac.h>
#include <string.h>
#define SALT_VALUE "mitosis"

bool
mitosis_hkdf_extract(const uint8_t* ikm, size_t ikm_len, uint8_t* prk) {
    MITOSIS_HMAC_STATE state;
    bool result = true;
    result = mitosis_hmac_init(&state, SALT_VALUE, sizeof(SALT_VALUE));
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
mitosis_hkdf_expand(const uint8_t* prk, size_t prk_len, const char* info, size_t info_len, uint8_t* okm, size_t okm_len) {
    MITOSIS_HMAC_STATE state;
    uint8_t scratch[MITOSIS_HMAC_OUTPUT_SIZE];
    bool result = true;
    if(okm_len > sizeof(scratch)) {
        return false;
    }

    result = mitosis_hmac_init(&state, prk, prk_len);
    if(!result) {
        return result;
    }
    result = mitosis_hmac_hash(&state, info, info_len);
    if(!result) {
        return result;
    }

    scratch[0] = 0x01;
    result = mitosis_hmac_hash(&state, scratch, 1);
    if(!result) {
        return result;
    }

    result = mitosis_hmac_complete(&state, scratch);
    if(!result) {
        return result;
    }

    memcpy(okm, scratch, okm_len);
    return result;
}
