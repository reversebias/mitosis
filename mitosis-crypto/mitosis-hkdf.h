/*
HKDF interface for Mitosis keyboard

Based on RFC 5869 (https://tools.ietf.org/html/rfc5869)
*/


bool mitosis_hkdf_extract(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt, size_t salt_len, uint8_t* prk);

bool mitosis_hkdf_expand(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len);
