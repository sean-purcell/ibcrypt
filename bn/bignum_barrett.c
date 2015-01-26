/* implementation of Barrett modular reduction */

#include <stdio.h>
#include <stdlib.h>

#include <bignum.h>
#include "bignum_util.h"

/* assumes that n is "trimmed" */
int bnu_barrett_mfactor(bignum *r, const bignum *n) {
	if(r == NULL || n == NULL) {
		return -1;
	}

	const uint64_t k2 = n->size * 64ULL * 2ULL;

	bignum four_k = BN_ZERO;
	if(bni_2power(&four_k, k2) != 0) {
		return 1;
	}

	if(bno_div(r, &four_k, n) != 0) {
		return 1;
	}

	return bnu_free(&four_k);
}

/* use the m factor to effect a modular reduction */
int bno_barrett_reduce(bignum *_r, const bignum *a, const bignum *m, const bignum *n) {
	if(_r == NULL || a == NULL || m == NULL || n == NULL) {
		return -1;
	}

	/* calculate q = floor(ma/4^k) */
	const uint64_t k2 = n->size * 64ULL * 2ULL;
	bignum q = BN_ZERO;
	if(bno_mul(&q, a, m) != 0) {
		return 1;
	}

	bno_rshift(&q, &q, k2);

	/* calculate r = a - qn */
	bignum qn = BN_ZERO;

	if(bno_mul(&qn, &q, n) != 0) {
		return 1;
	}

	if(bno_sub(_r, a, &qn) != 0) {
		return 1;
	}

	if(bno_cmp(_r, n) >= 0) {
		if(bno_sub(_r, _r, n) != 0) {
			return 1;
		}
	}

	return bnu_free(&q) || bnu_free(&qn);
}

int bno_barrett_rmod(bignum *_r, const bignum *a, const bignum *n) {
	if(_r == NULL || a == NULL || n == NULL) {
		return -1;
	}

	bignum m = BN_ZERO;
	if(bnu_barrett_mfactor(&m, n) != 0) {
		return 1;
	}

	if(bno_barrett_reduce(_r, a, &m, n) != 0) {
		return 1;
	}

	return bnu_free(&m);
}
