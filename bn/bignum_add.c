#include "bignum.h"
#include "bignum_util.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
int bno_uadd(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	if(r == NULL || a == NULL || b == NULL) {
		return -1;
	}

	/* TODO: bounds checking */
	bnu_resize(r, max(a->size, b->size) + 1);
}

int bno_add(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	if(a->neg == b->neg) {
		return bno_uadd(r, a, b);
	} else {
		return bno_usub(r, a, b);
	}
}
