#ifndef IBCRYPT_SHA256_H
#define IBCRYPT_SHA256_H

#include <stdint.h>

typedef struct sha256_context {
	uint32_t state[8];
	uint64_t count;
	uint8_t buf[64];
} SHA256_CTX;

void sha256_init(SHA256_CTX* ctx);
void sha256_update(SHA256_CTX* ctx, uint8_t* message, uint64_t msize);
void sha256_final(SHA256_CTX* ctx, uint8_t sum[32]);

void sha256(uint8_t* message, uint64_t osize, uint8_t* out);

void hmac_sha256(uint8_t* key, uint32_t keylen, uint8_t* message, uint32_t len, uint8_t* out);

void pbkdf2_hmac_sha256(uint8_t* pass, uint32_t plen, uint8_t* salt, uint32_t saltLen, uint32_t c, uint32_t dkLen, uint8_t* out);

#endif
