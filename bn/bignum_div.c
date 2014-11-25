#include <stdlib.h>

#include <bignum.h>
#include "bignum_util.h"

// returns floor(a / b)
int bno_div(BIGNUM *q, const BIGNUM *a, const BIGNUM *b) {
	return bno_div_mod(q, NULL, a, b);
}

int bno_div_mod(BIGNUM *q, BIGNUM *r, const BIGNUM *a, const BIGNUM *b) {
	if(q == NULL || a == NULL || b == NULL) {
		return -1;
	}

	if(bno_cmp(a, b) < 0) {
		return bnu_resize(q, 0);
	}

	BIGNUM nt = BN_ZERO;
	BIGNUM at = BN_ZERO;
	if(bni_cpy(&nt, b) != 0 || bni_cpy(&at, a) != 0) {
		return 1;
	}

	uint64_t shift = 0;
	/* shift nt so that its greater than a */
	while(bno_cmp(&nt, &at) <= 0) {
		if(bno_lshift(&nt, &nt, 32) != 0) {
			return 1;
		}
		shift += 32;
	}

	if(bnu_resize(q, 0) != 0 || bnu_resize(q, (shift+63)/64) != 0) {
		return 1;
	}

	const uint64_t o_shift = shift;
	for(uint64_t i = 0; i < shift; i++) {
		rshift_words(nt.d, nt.d, nt.size-(i/64), 1);
		if(cmp_words(nt.d, nt.size-(i/64), at.d, at.size) <= 0) {
			sub_words(at.d, at.d, at.size, nt.d, nt.size-(i/64));
			const uint64_t bit = o_shift - i - 1;
			q->d[bit/64] |= 1ULL << (bit%64);
		}
	}

	if(r != NULL && bni_cpy(r, &at) != 0) {
		return 1;
	}

	bnu_free(&nt);
	bnu_free(&at);

	return bnu_trim(q) || (r != NULL ? bnu_trim(r) : 0);
}
