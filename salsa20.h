#ifndef IBCRYPT_SALSA20_H
#define IBCRYPT_SALSA20_H

/* the salsa20 core hash function
 * in and out can overlap */
void salsa20_core(const uint8_t in[64], uint8_t out[64]);

/* the salsa20expansion function 
 * ksize must be 16 or 32, otherwise
 * this function will fail silently */
void salsa20_expand(const uint8_t* const k, const uint8_t ksize, const uint8_t n[16], uint8_t out[64]);

#endif
