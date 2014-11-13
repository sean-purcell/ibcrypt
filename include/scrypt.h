#ifndef IBCRYPT_SCRYPT_H
#define IBCRYPT_SCRYPT_H

#include <stdint.h>

int scrypt(void* pass, uint32_t plen, uint8_t* salt, uint32_t slen,
	uint64_t N, uint32_t r, uint32_t p, size_t dkLen, uint8_t* out);

#endif
