#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "mitosis-crypto.h"


extern bool mitosis_crypto_init(mitosis_crypto_context_t* context, mitosis_crypto_key_type_t type);

extern bool mitosis_crypto_rekey(mitosis_crypto_context_t* context, mitosis_crypto_key_type_t type, const uint8_t* seed, size_t seed_len);
