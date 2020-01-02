/*
CKDF interface for Mitosis keyboard

Based on draft-agl-ckdf-01 (https://tools.ietf.org/html/draft-agl-ckdf-01)
*/


bool mitosis_ckdf_extract(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt, size_t salt_len, uint8_t* prk);

bool mitosis_ckdf_expand(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len);
