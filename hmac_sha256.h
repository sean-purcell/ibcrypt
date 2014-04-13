#ifndef IBUR_HMAC_SHA256_H
#define IBUR_HMAC_SHA256_H

#include <stdint.h>

void hmac_sha256(const uint8_t* const key, const uint32_t keylen, const uint8_t* const message, uint32_t len, uint8_t* const out);

#endif
