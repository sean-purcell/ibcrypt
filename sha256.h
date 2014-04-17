#ifndef IBCRYPT_SHA256_H
#define IBCRYPT_SHA256_H

#include <stdint.h>

#define SHA_256_DEBUG 0

void sha256(const uint8_t* message, const uint64_t osize, uint8_t* const out);

void hmac_sha256(const uint8_t* const key, const uint32_t keylen, const uint8_t* const message, uint32_t len, uint8_t* const out);

void pbkdf2_hmac_sha256(const uint8_t* const pass, const uint32_t plen, const uint8_t* salt, const uint32_t saltLen, const uint32_t c, const uint32_t dkLen, uint8_t* const out);

#endif
