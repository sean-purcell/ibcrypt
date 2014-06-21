#include "bignum.h"
#include "bignum_util.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
int bno_uadd(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	if(r == NULL || a == NULL || b == NULL) {
		return -1;
	}

	/* TODO: bounds checking */
	bnu_resize(r, max(a->size, b->size) + 1);

	uint64_t t0, t1;
	uint32_t i;
	int carry = 0;
	for(i = 0; i < min(a->d, b->d); i++) {
		t0 = a->d[i] + carry;
		carry = (t0 < a->d[i]); /* C standard 3.3.8 */
		t1 = t0 + b->d[i];
		carry = (t1 < t0);
		r->d[i] = t1;
	}

	r->neg = a->neg;

	bnu_trim(r);

	return 0;
}

int bno_usub(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	
}

int bno_add(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	if(a->neg == b->neg) {
		return bno_uadd(r, a, b);
	} else {
		return bno_usub(r, a, b);
	}
}
