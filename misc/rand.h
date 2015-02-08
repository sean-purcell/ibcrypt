#ifndef IBCRYPT_RAND_H
#define IBCRYPT_RAND_H

#define RANDOM_FAIL 1

#include <stdlib.h>
#include <stdint.h>

// returns URANDOM_FAIL if unsuccessful
int cs_rand(void* buf, size_t buflen);

int cs_rand_uint64(uint64_t* r);
int cs_rand_uint64_range(uint64_t* r, uint64_t top);

int cs_rand_uint32(uint32_t* r);
int cs_rand_uint32_range(uint32_t* r, uint32_t top);

#endif
