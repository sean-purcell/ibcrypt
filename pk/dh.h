#ifndef IBCRYPT_PK_DH_H
#define IBCRYPT_PK_DH_H

#include <stdint.h>

#ifdef IBCRYPT_BUILD
#include "../bn/bignum.h"
#else
#include <ibcrypt/bignum.h>
#endif

typedef struct {
	bignum p;
	bignum g;
	uint64_t bits;
} DH_CTX;

int dh_init_ctx(DH_CTX *ctx, int id);

#endif

