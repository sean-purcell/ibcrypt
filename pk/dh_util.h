#ifndef IBCRYPT_PK_DH_UTIL_H
#define IBCRYPT_PK_DH_UTIL_H

#ifdef IBCRYPT_BUILD
#include "dh.h"
#else
#include <ibcrypt/dh.h>
#endif

int dh_val2wire(DH_VAL *v, uint8_t *out, uint64_t outlen);
int dh_wire2val(uint8_t *in, uint64_t inlen, DH_VAL *v);
size_t dh_valwire_bufsize(DH_VAL *v);

#endif

