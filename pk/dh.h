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
	bignum q;
	bignum g;
	uint64_t bits;
} DH_CTX;

typedef struct {
	bignum x;
} DH_VAL;

typedef DH_VAL DH_PRI;
typedef DH_VAL DH_PUB;

extern DH_VAL DH_VAL_INIT;

int dh_init_ctx(DH_CTX *ctx, int id);
int dh_free_ctx(DH_CTX *ctx);
int dh_gen_exp(DH_CTX *ctx, DH_PRI *e);
int dh_gen_pub(DH_CTX *ctx, DH_PRI *e, DH_PUB *x);
int dh_compute_secret(DH_CTX *ctx, DH_PRI *e, DH_PUB *x, DH_VAL *s);
int dh_val_init(DH_VAL *v);
int dh_val_free(DH_VAL *v);
int dh_range_check(DH_CTX *ctx, DH_PUB *v);

#endif

