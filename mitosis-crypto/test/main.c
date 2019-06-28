#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "mitosis-hmac.h"

void print_hex(char* label, uint8_t* bytes, size_t len) {
    for(int idx = 0; idx < len; ++idx) {
        if(idx == 0) {
            printf("%s:\t%02x ", label, bytes[idx]);
        } else if (idx == len - 1) {
            printf("%02x\n", bytes[idx]);
        } else {
            printf("%02x ", bytes[idx]);
        }
    }
}

bool hmac_sha256_kat() {
    MITOSIS_HMAC_STATE state = { 0 };
    uint8_t key[] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
    if(!mitosis_hmac_init(&state, (uint8_t*)key, sizeof(key))) {
        printf("%s: failed HMAC init\n", __func__);
        return false;
    }

    uint8_t data[] = { 0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65 };
    if(!mitosis_hmac_hash(&state, data, sizeof(data))) {
        printf("%s: failed HMAC hash\n", __func__);
        return false;
    }
    uint8_t result[MITOSIS_HMAC_OUTPUT_SIZE] = { 0 };
    if(!mitosis_hmac_complete(&state, result)) {
        printf("%s: failed HMAC complete\n", __func__);
        return false;
    }

    uint8_t expected[MITOSIS_HMAC_OUTPUT_SIZE] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };

    if(memcmp(result, expected, sizeof(result)) != 0) {
        printf("%s: expected HMAC doesn't match actual\n", __func__);
        print_hex("Actual  ", result, sizeof(result));
        print_hex("Expected", expected, sizeof(expected));
        int idx = 0;
        while(result[idx] == expected[idx]) ++idx;
        printf("Index %d doesn't match (%02x actual vs. %02x expected)\n", idx, result[idx], expected[idx]);
        return false;
    }
    return true;
}

int main(int argc, char** argv) {
    hmac_sha256_kat();
    return 0;
}
