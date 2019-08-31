#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "mitosis-crypto.h"

bool mitosis_generate_keyboard_keys(bool left, uint8_t* output_encrypt_key, size_t encrypt_key_len, uint8_t* output_hmac_key, size_t hmac_key_len, uint8_t* output_encrypt_nonce, size_t nonce_len) {

    bool result = true;
    uint8_t ikm[sizeof((uint8_t[])MITOSIS_MASTER_SECRET_SEED)] = MITOSIS_MASTER_SECRET_SEED;
    uint8_t prk[MITOSIS_HMAC_OUTPUT_SIZE];

    result =
        mitosis_hkdf_extract(
            ikm, sizeof(ikm),
            (uint8_t*)(left ? MITOSIS_LEFT_SALT : MITOSIS_RIGHT_SALT),
            (left ? sizeof(MITOSIS_LEFT_SALT) : sizeof(MITOSIS_RIGHT_SALT)),
            prk);
    if(!result) {
        return result;
    }

    result = mitosis_hkdf_expand(prk, sizeof(prk), (uint8_t*)MITOSIS_ENCRYPT_KEY_INFO, sizeof(MITOSIS_ENCRYPT_KEY_INFO), output_encrypt_key, encrypt_key_len);
    if(!result) {
        return result;
    }

    result = mitosis_hkdf_expand(prk, sizeof(prk), (uint8_t*)MITOSIS_HMAC_KEY_INFO, sizeof(MITOSIS_HMAC_KEY_INFO), output_hmac_key, hmac_key_len);
    if(!result) {
        return result;
    }

    result = mitosis_hkdf_expand(prk, sizeof(prk), (uint8_t*)MITOSIS_NONCE_INFO, sizeof(MITOSIS_NONCE_INFO), output_encrypt_nonce, nonce_len);

    return result;
}
