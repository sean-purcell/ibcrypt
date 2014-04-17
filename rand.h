#ifndef IBUR_RAND_H
#define IBUR_RAND_H

#define URANDOM_FAIL 1

#include <stdlib.h>

// returns URANDOM_FAIL if unsuccessful
int cs_rand(uint8_t* buf, uint32_t buflen);

#endif
