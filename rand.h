#ifndef IBCRYPT_RAND_H
#define IBCRYPT_RAND_H

#define URANDOM_FAIL 1

#include <stdlib.h>
#include <stdint.h>

// returns URANDOM_FAIL if unsuccessful
int cs_rand(uint8_t* buf, uint32_t buflen);

uint32_t cs_rand_int();

#endif
