#include <stdint.h>

#define IBCRYPT_BUILD
#include "dh.h"
#include "rsa.h"
#undef IBCRYPT_BUILD

#include "../bn/bignum.h"
#include "../bn/bignum_util.h"

extern uint64_t  RFC3526_BITS[];
extern char     *RFC3526_GROUPS[];

static uint64_t bottom_limit_val = 8193;
static bignum bottom_limit = { &bottom_limit_val, 1 };

DH_VAL DH_VAL_INIT = { { NULL, 0 } };

/* the id refers to the group ids defined in rfc3526
 * only groups 14-18 are included */
int dh_init_ctx(DH_CTX *ctx, int id) {
	if(id < 14 || id > 18) {
		return -1;
	}

	memset(ctx, 0, sizeof(DH_CTX));
	if(bni_fstr(&ctx->p, RFC3526_GROUPS[id - 14]) != 0) {
		return -1;
	}
	if(bno_rshift(&ctx->q, &ctx->p, 1) != 0) {
		return -1;
	}
	if(bni_cpy(&ctx->g, &TWO) != 0) {
		return -1;
	}

	ctx->bits = RFC3526_BITS[id - 14];

	return 0;
}

int dh_free_ctx(DH_CTX *ctx) {
	return bnu_free(&ctx->p) ||
	       bnu_free(&ctx->q) ||
	       bnu_free(&ctx->g);
}

int dh_gen_exp(DH_CTX *ctx, DH_PRI *e) {
	memset(e, 0, sizeof(DH_PRI));
	return bni_rand_range(&e->x, &bottom_limit, &ctx->q);
}

int dh_gen_pub(DH_CTX *ctx, DH_PRI *e, DH_PUB *x) {
	memset(x, 0, sizeof(DH_PRI));
	return bno_exp_mod(&x->x, &ctx->g, &e->x, &ctx->p);
}

int dh_compute_secret(DH_CTX *ctx, DH_PRI *e, DH_PUB *x, DH_VAL *s) {
	memset(s, 0, sizeof(DH_VAL));
	return bno_exp_mod(&s->x, &x->x, &e->x, &ctx->p);
}

int dh_val_init(DH_VAL *v) {
	memset(v, 0, sizeof(DH_VAL));
	return 0;
}

int dh_val_free(DH_VAL *v) {
	return bnu_free(&v->x);
}

