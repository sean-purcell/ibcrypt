#ifndef IBUR_AES_H
#define IBUR_AES_H

// Max number of possible rounds
#define MAX_RNDS 14
// Turn on state outputs
#define AES_DEBUG 0

struct aes_key_struct {
	unsigned char rd_key[16 * (MAX_RNDS + 1)];
	int rounds;
};

typedef struct aes_key_struct AES_KEY;

int create_key_AES(const unsigned char* const source, const int bits, AES_KEY* const key);

void encrypt_block_AES(const unsigned char* const in, unsigned char* const out, const AES_KEY* const key);

void decrypt_block_AES(const unsigned char* const in, unsigned char* const out, const AES_KEY* const key);

#endif
