#ifndef _MITOSIS_CRYPTO_H
#define _MITOSIS_CRYPTO_H

#include "mitosis-hmac.h"
#include "mitosis-hkdf.h"
#include "mitosis-ckdf.h"
#include "mitosis-aes-ctr.h"
#include "mitosis-cmac.h"

/*
    CHANGE THIS VALUE TO BE UNIQUE TO YOUR MITOSIS KEYBOARD.
    IT MUST BE AT LEAST 16 BYTES LONG.
    You can get random bytes from, for example, https://www.random.org/bytes/
    or the following shell script:
    od -vN 16 -An -tx1 /dev/urandom | sed -E 's/^ /0x/; s/ /, 0x/g;'
*/
#define MITOSIS_MASTER_SECRET_SEED { 0xd4, 0xec, 0x88, 0x1e, 0x32, 0x0e, 0x97, 0x86, 0xf2, 0xdb, 0x75, 0xfa, 0x73, 0xda, 0x8a, 0x10 }

/*
    THESE SALT VALUES MUST BE EXACTLY 16 BYTES LONG.
    These salt values are byte arrays because CKDF uses the SALT as an AES key.
*/
#define MITOSIS_LEFT_SALT { 0xa9, 0x09, 0xb0, 0x9d, 0x36, 0x4d, 0xc2, 0x40, 0xeb, 0x37, 0xcb, 0x13, 0xf3, 0xb3, 0xe6, 0x41 }

#define MITOSIS_RIGHT_SALT { 0x99, 0x3f, 0xfc, 0x88, 0xbf, 0x21, 0x44, 0x90, 0xf0, 0x2b, 0x53, 0x2e, 0x02, 0xff, 0x7e, 0xc5 }

#define MITOSIS_RECEIVER_SALT { 0xff, 0xe5, 0x5d, 0xcc, 0x7b, 0xce, 0x11, 0x1f, 0xb3, 0xb6, 0xe8, 0x7e, 0xa3, 0x81, 0xe0, 0x49 }

#define MITOSIS_ENCRYPT_KEY_INFO "encryption key"

#define MITOSIS_CMAC_KEY_INFO "MAC key"

#define MITOSIS_NONCE_INFO "encryption nonce"

/*
    The number of encryptions a keyboard half can do before the receiver tells it
    to update the keys. This doesn't cleanly map to keypresses, since a single
    press may generate tens of packets.

    Note: Values less than 30 seem cause problems.
    And anything less than 1,000,000,000 is overkill.
*/
#define MITOSIS_REKEY_INTERVAL 100000

typedef struct _mitosis_crypto_context_t {
    mitosis_encrypt_context_t encrypt;
    mitosis_cmac_context_t cmac;
} mitosis_crypto_context_t;

typedef struct _mitosis_crypto_data_payload_t {
    union {
        struct {
            uint8_t  data[3];
            uint8_t key_id;
            uint32_t counter;
        };
        uint8_t payload[8];
    };
    uint8_t  mac[16];
} mitosis_crypto_data_payload_t;

_Static_assert(sizeof(mitosis_crypto_data_payload_t) == 24);

typedef struct _mitosis_crypto_seed_payload_t {
    union {
        struct {
            uint8_t seed[15];
            uint8_t key_id;
        };
        uint8_t payload[16];
    };
    uint8_t mac[16];
} mitosis_crypto_seed_payload_t;

_Static_assert(sizeof(mitosis_crypto_seed_payload_t) == 32);

typedef enum _mitosis_crypto_key_type_t {
    right_keyboard_crypto_key,
    left_keyboard_crypto_key,
    receiver_crypto_key
} mitosis_crypto_key_type_t;


inline
bool
mitosis_crypto_rekey(mitosis_crypto_context_t* context, mitosis_crypto_key_type_t type, const uint8_t* seed, size_t seed_len)
{
    bool result = true;
    uint8_t prk[MITOSIS_CMAC_OUTPUT_SIZE];
    static const uint8_t left_salt[sizeof((uint8_t[]) MITOSIS_LEFT_SALT)] = MITOSIS_LEFT_SALT;
    static const uint8_t right_salt[sizeof((uint8_t[]) MITOSIS_RIGHT_SALT)] = MITOSIS_RIGHT_SALT;
    static const uint8_t receiver_salt[sizeof((uint8_t[]) MITOSIS_RECEIVER_SALT)] = MITOSIS_RECEIVER_SALT;
    const uint8_t* salt;
    size_t salt_len;

    switch(type)
    {
        case right_keyboard_crypto_key:
            salt = right_salt;
            salt_len = sizeof(right_salt);
            break;
        case left_keyboard_crypto_key:
            salt = left_salt;
            salt_len = sizeof(left_salt);
            break;
        case receiver_crypto_key:
            salt = receiver_salt;
            salt_len = sizeof(receiver_salt);
            break;
        default:
            return false;
    }

    result =
        mitosis_ckdf_extract(
            seed, seed_len,
            salt, salt_len,
            prk);
    if (!result)
    {
        return result;
    }

    result =
        mitosis_ckdf_expand(
            prk, sizeof(prk),
            (uint8_t*)MITOSIS_ENCRYPT_KEY_INFO, sizeof(MITOSIS_ENCRYPT_KEY_INFO),
            context->encrypt.ctr.key, sizeof(context->encrypt.ctr.key));
    if (!result)
    {
        return result;
    }

    result =
        mitosis_ckdf_expand(
            prk, sizeof(prk),
            (uint8_t*)MITOSIS_NONCE_INFO,
            sizeof(MITOSIS_NONCE_INFO),
            context->encrypt.ctr.iv_bytes, sizeof(context->encrypt.ctr.iv_bytes));
    if (!result)
    {
        return result;
    }

    // Initialize counter to zero.
    context->encrypt.ctr.iv.counter = 0;

    // prk can be overwritten here because mitosis_ckdf_expand is done with it
    // by the time that output is being written.
    result =
        mitosis_ckdf_expand(
            prk, sizeof(prk),
            (uint8_t*)MITOSIS_CMAC_KEY_INFO, sizeof(MITOSIS_CMAC_KEY_INFO),
            prk, AES_BLOCK_SIZE);
    if (!result)
    {
        return result;
    }

    if (!mitosis_cmac_init(&(context->cmac), prk, sizeof(prk)))
    {
        return false;
    }

    return mitosis_aes_ecb_init(&(context->encrypt.ecb));
}

inline
bool
mitosis_crypto_init(mitosis_crypto_context_t* context, mitosis_crypto_key_type_t type)
{
    static const uint8_t ikm[sizeof((uint8_t[])MITOSIS_MASTER_SECRET_SEED)] = MITOSIS_MASTER_SECRET_SEED;
    return mitosis_crypto_rekey(context, type, ikm, sizeof(ikm));
}

#endif // _MITOSIS_CRYPTO_H
