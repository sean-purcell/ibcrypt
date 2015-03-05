#include <stdint.h>

#define IBCRYPT_BUILD
#include "dh.h"
#undef IBCRYPT_BUILD

#include "../bn/bignum.h"

extern uint64_t  RFC3526_BITS[];
extern char     *RFC3526_GROUPS[];

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

	ctx->g = TWO;
	ctx->bits = RFC3526_BITS[id - 14];

	return 0;
}

