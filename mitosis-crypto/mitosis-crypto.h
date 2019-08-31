#ifndef _MITOSIS_CRYPTO
#define _MITOSIS_CRYPTO

#include "mitosis-hmac.h"
#include "mitosis-hkdf.h"
#include "mitosis-aes-ctr.h"

/*
    CHANGE THIS VALUE TO BE UNIQUE TO YOUR MITOSIS KEYBOARD.
    You can get random bytes from, for example, https://www.random.org/bytes/
    or the following shell script:
    od -vN 16 -An -tx1 /dev/urandom | tr -d "\n" ; echo
*/
#define MITOSIS_MASTER_SECRET_SEED { 0x30, 0x54, 0xaf, 0x7e, 0x1a, 0x22, 0xfa, 0x8e, 0x29, 0xb6, 0x0b, 0x13, 0x26, 0x67, 0xd3, 0x85 }

#define MITOSIS_LEFT_SALT "mitosis left keyboard"

#define MITOSIS_RIGHT_SALT "mitosis right keyboard"

#define MITOSIS_ENCRYPT_KEY_INFO "encryption key"

#define MITOSIS_HMAC_KEY_INFO "MAC key"

#define MITOSIS_NONCE_INFO "encryption nonce"

typedef struct _mitosis_crypto_context_t {
    mitosis_hmac_context_t hmac;
    mitosis_encrypt_context_t encrypt;
} mitosis_crypto_context_t;


bool mitosis_crypto_init(mitosis_crypto_context_t* context, bool left);

#endif // _MITOSIS_CRYPTO
