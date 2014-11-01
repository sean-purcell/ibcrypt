/* implementation of Barrett modular reduction */

#include <stdio.h>
#include <stdlib.h>

#include "bignum.h"
#include "bignum_util.h"

/* get 2 to the power of k */
int bnu_2power(BIGNUM* _r, const uint64_t k) {
	if(_r == NULL) {
		return -1;
	}

	const uint64_t block = k / 64;
	const uint64_t size = block + 1;
	const uint64_t shift = k % 64;
	if(size > 0xffffffffULL) {
		return 1; /* too big */
	}

	BIGNUM r = BN_ZERO;
	if(bnu_resize(&r, size) != 0) {
		return 1; /* failed to resize */
	}

	r.d[block] = 1ULL << shift;
	*_r = r;

	return 0;
}

/* assumes that n is "trimmed" */
int bnu_barrett_mfactor(BIGNUM* r, const BIGNUM* n) {
	if(r == NULL || n == NULL) {
		return -1;
	}

	const uint64_t k2 = n->size * 64ULL * 2ULL;

	BIGNUM four_k = BN_ZERO;
	if(bnu_2power(&four_k, k2) != 0) {
		return 1;
	}

	char out[10000];
	bnu_tstr(out, &four_k);
	printf("four_k:%s\n", out);

	if(bno_div(r, &four_k, n) != 0) {
		return 1;
	}

	return bnu_free(&four_k);
}

/* use the m factor to effect a modular reduction */
int bno_barrett_reduce(BIGNUM* _r, const BIGNUM* a, const BIGNUM* m, const BIGNUM* n) {
	if(_r == NULL || a == NULL || m == NULL || n == NULL) {
		return -1;
	}

	/* calculate q = floor(ma/4^k) */
	const uint64_t k2 = n->size * 64ULL * 2ULL;
	BIGNUM q = BN_ZERO;
	if(bno_mul(&q, a, m) != 0) {
		return 1;
	}

	bno_rshift(&q, &q, k2);

	/* calculate r = a - qn */
	BIGNUM qn = BN_ZERO;

	if(bno_mul(&qn, &q, n) != 0) {
		return 1;
	}

	if(bno_sub(_r, a, &qn) != 0) {
		return 1;
	}

	return bnu_free(&q) || bnu_free(&qn);
}

int bno_barrett_rmod(BIGNUM* _r, const BIGNUM* a, const BIGNUM* n) {
	if(_r == NULL || a == NULL || n == NULL) {
		return -1;
	}

	BIGNUM m = BN_ZERO;
	if(bnu_barrett_mfactor(&m, n) != 0) {
		return 1;
	}
	char out[10000];
	bnu_tstr(out, &m);
	printf("m:%s\n", out);

	if(bno_barrett_reduce(_r, a, &m, n) != 0) {
		return 1;
	}

	return bnu_free(&m);
}
