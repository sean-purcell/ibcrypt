#ifndef IBCRYPT_SHA256_H
#define IBCRYPT_SHA256_H

#include <stdint.h>

typedef struct sha256_context {
	uint32_t state[8];
	uint64_t count;
	uint8_t buf[64];
} SHA256_CTX;

typedef struct hmac_sha256_context {
	SHA256_CTX ictx,
	           octx;
} HMAC_SHA256_CTX;

/* must be run on a new context before use */
void sha256_init(SHA256_CTX* ctx);
/* process data */
void sha256_update(SHA256_CTX* ctx, const uint8_t* message, uint32_t msize);
/* pads the data and computes the final hash.  zeroes context as well */
void sha256_final(SHA256_CTX* ctx, uint8_t sum[32]);

/* combination of init, update, and final for ease of use */
void sha256(const uint8_t* message, uint64_t osize, uint8_t* out);

/* initialize the hmac_sha256 context with the given key */
void hmac_sha256_init(HMAC_SHA256_CTX* ctx, const uint8_t* key, uint32_t keylen);
/* process message data */
void hmac_sha256_update(HMAC_SHA256_CTX* ctx, uint8_t* message, uint32_t mlen);
/* computes the final mac */
void hmac_sha256_final(HMAC_SHA256_CTX* ctx, uint8_t mac[32]);

/* combination of init, update, and final for ease of use */
void hmac_sha256(uint8_t* key, uint32_t keylen, uint8_t* message, uint32_t len, uint8_t* out);

void pbkdf2_hmac_sha256(uint8_t* pass, uint32_t plen, uint8_t* salt, uint32_t saltLen, uint32_t c, uint32_t dkLen, uint8_t* out);

#endif
