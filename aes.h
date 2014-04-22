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
	uint8_t prev[16];
	uint32_t count;
} AES_CBC_CTX;

int create_key_AES(const uint8_t* const source, const int bits, AES_KEY* const key);

void encrypt_block_AES(const uint8_t* const in, uint8_t* const out, const AES_KEY* const key);

void decrypt_block_AES(const uint8_t* const in, uint8_t* const out, const AES_KEY* const key);

void zero_key_AES(AES_KEY* const key);

int encrypt_cbc_AES(const uint8_t* const message, const uint32_t length, const uint8_t* const iv, const AES_KEY* const key, uint8_t* const out);

int decrypt_cbc_AES(const uint8_t* const message, const uint32_t length, const uint8_t* const iv, const AES_KEY* const key, uint8_t* const out);

int encrypt_ctr_AES(const uint8_t* const message, const uint32_t length, const uint8_t nonce[16], const AES_KEY* const key, uint8_t* const out);

int decrypt_ctr_AES(const uint8_t* const message, const uint32_t length, const uint8_t nonce[16], const AES_KEY* const key, uint8_t* const out);

#endif
