#ifndef IBCRYPT_AES_H
#define IBCRYPT_AES_H

#include <stdint.h>

// Max number of possible rounds
#define MAX_RNDS 14
// Turn on state outputs
#define AES_DEBUG 0

typedef struct {
	uint8_t rd_key[16 * (MAX_RNDS + 1)];
	int rounds;
} AES_KEY;

typedef struct {
	AES_KEY key;
	uint8_t stream[16];
	uint8_t nonce[16];
	uint64_t count;
} AES_CTR_CTX;

int create_key_AES(const uint8_t* const source, const int bits, AES_KEY* const key);

void encrypt_block_AES(const uint8_t* const in, uint8_t* const out, const AES_KEY* const key);

void decrypt_block_AES(const uint8_t* const in, uint8_t* const out, const AES_KEY* const key);

void zero_key_AES(AES_KEY* const key);

int encrypt_cbc_AES(const uint8_t* const message, const uint32_t length, const uint8_t* const iv, const AES_KEY* const key, uint8_t* const out);

int decrypt_cbc_AES(const uint8_t* const message, const uint32_t length, const uint8_t* const iv, const AES_KEY* const key, uint8_t* const out);

/* initialize an aes ctr context.  recommended for large messages instead of putting it all in one buffer */
AES_CTR_CTX* init_ctr_AES(const AES_KEY* const key, const uint8_t* const nonce, const uint32_t noncelen);

/* encrypt/decrypt a block of ctr 
 * if in and out overlap they must be identical*/
void stream_ctr_AES(AES_CTR_CTX* const ctx, const uint8_t* const in, const size_t len, uint8_t* const out);

/* free the context and zero the memory */
void free_ctr_AES(AES_CTR_CTX* ctx);

int encrypt_ctr_AES(const uint8_t* const message, const uint32_t length, const uint8_t nonce[16], const AES_KEY* const key, uint8_t* const out);

int decrypt_ctr_AES(const uint8_t* const message, const uint32_t length, const uint8_t nonce[16], const AES_KEY* const key, uint8_t* const out);

#endif
