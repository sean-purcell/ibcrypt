#ifndef IBCRYPT_SALSA20_H
#define IBCRYPT_SALSA20_H

//#define SALSA20_DEBUG

typedef struct {
	uint64_t nonce;
	uint64_t count;
	uint8_t key[32];
	int ksize;
	uint8_t stream[64];
} SALSA20_CTX;

/* the salsa20 core hash function
 * in and out can overlap */
void salsa20_core(const uint8_t in[64], uint8_t out[64]);

/* the salsa20expansion function 
 * ksize must be 16 or 32, otherwise
 * this function will fail silently */
void salsa20_expand(const uint8_t* const k, const int ksize, const uint8_t n[16], uint8_t out[64]);

/* initialize a salsa20 context
 * returns NULL on failure 
 * ksize is in bytes */
SALSA20_CTX* init_salsa20(const uint8_t* key, const int ksize, const uint64_t nonce);

/* encrypt/decrypt a section */
void stream_salsa20(SALSA20_CTX* ctx, const uint8_t* const in, uint8_t* const out, const uint64_t len);

/* frees an initialized salsa20 context */
void free_salsa20(SALSA20_CTX* ctx);

/* convenience functions */
int salsa20_enc(const uint8_t* key, const int ksize, const uint64_t nonce, const uint8_t* const in, uint8_t* const out, const uint64_t len);
int salsa20_dec(const uint8_t* key, const int ksize, const uint64_t nonce, const uint8_t* const in, uint8_t* const out, const uint64_t len);

#endif
