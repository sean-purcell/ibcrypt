#include <stdlib.h>
#include <stdint.h>

#include "bignum.h"
#include "bignum_util.h"

int bno_mul_fst(BIGNUM* r, const BIGNUM* _a, const BIGNUM* _b) {
	if(r == NULL || _a == NULL || _b == NULL) {
		return -1;
	}

	BIGNUM a = BN_ZERO;
	BIGNUM b = BN_ZERO;
	if(bni_cpy(&a, _a) != 0 || bni_cpy(&b, _b) != 0) {
		return 1;
	}

	uint64_t size = a.size * b.size;
	if(size > 0xffffffffU) {
		return 2; /* too big */
	}

	if(bnu_resize(r, 0) != 0) {
		return 1;
	}

	const uint64_t ablks = a.size * 2;
	const uint64_t bblks = b.size * 2;

	BIGNUM tmp = BN_ZERO;

	/* long multiplication with 32 bit digits */
	uint64_t i, j;
	for(i = 0; i < ablks; i++) {
		for(j = 0; j < bblks; j++) {
			if(bnu_resize(&tmp, 1) != 0) {
				return 1;
			}

			tmp.d[0] = (a.d[i/2] & ((uint64_t)0xffffffff << (32 * (i&1)))) >> (32 * (i&1));
			tmp.d[0] *= (b.d[j/2] & ((uint64_t)0xffffffff << (32 * (j&1)))) >> (32 * (j&1));

			if(bno_lshift(&tmp, &tmp, (i+j) * 32) != 0) {
				return 1;
			}
			if(bno_add(r, r, &tmp) != 0) {
				return 1;
			}
		}
	}

	r->neg = _a->neg != _b->neg;

	return bnu_free(&a) | bnu_free(&b) | bnu_free(&tmp);
}

int bno_mul(BIGNUM* r, const BIGNUM* _a, const BIGNUM* _b) {
	if(r == NULL || _a == NULL || _b == NULL) {
		return -1;
	}

	uint64_t size = _a->size * _b->size;
	if(size > 0xffffffffU) {
		return 2; /* too big */
	}

	BIGNUM a = BN_ZERO;
	BIGNUM b = BN_ZERO;
	if(bni_cpy(&a, _a) != 0 || bni_cpy(&b, _b) != 0) {
		return 1;
	}

	if(bnu_resize(r, 0) != 0) {
		return 1;
	}

	uint32_t i;
	uint64_t lpos = 0;
	for(i = 0; i < b.size; i++) {
		int j;
		for(j = 0; j < 64; j++) {
			/* if bit is set */
			if(b.d[i] & ((uint64_t)1 << j)) {
				if(bno_lshift(&a, &a, ((uint64_t)i * 64 + j) - lpos) != 0) {
					return 1;
				}

				if(bno_uadd(r, r, &a) != 0) {
					return 1;
				}
				lpos = i * 64 + j;
			}
		}
	}

	bnu_free(&a);
	bnu_free(&b);

	r->neg = _a->neg != _b->neg;
	return bnu_trim(r);
}

int bno_mul_mod(BIGNUM* r, const BIGNUM* _a, const BIGNUM* _b, const BIGNUM* n) {
	if(r == NULL || _a == NULL || _b == NULL || n == NULL) {
		return -1;
	}

	uint64_t size = _a->size * _b->size;
	if(size > 0xffffffffU) {
		return 2; /* too big */
	}

	BIGNUM a = BN_ZERO;
	BIGNUM b = BN_ZERO;
	if(bni_cpy(&a, _a) != 0 || bni_cpy(&b, _b) != 0) {
		return 1;
	}

	if(bno_rmod(&a, &a, n) != 0 || bno_rmod(&b, &b, n) != 0) {
		return 1;
	}

	if(bnu_resize(r, 0) != 0) {
		return 1;
	}

	uint32_t i;
	uint64_t lpos = 0;
	for(i = 0; i < b.size; i++) {
		int j;
		for(j = 0; j < 64; j++) {
			/* if bit is set */
			if(b.d[i] & ((uint64_t)1 << j)) {
				if(bno_lshift(&a, &a, ((uint64_t)i * 64 + j) - lpos) != 0) {
					return 1;
				}
				if(bno_rmod(&a, &a, n) != 0) {
					return 1;
				}

				if(bno_uadd_mod(r, r, &a, n) != 0) {
					return 1;
				}
				lpos = i * 64 + j;
			}
		}
	}

	bnu_free(&a);
	bnu_free(&b);

	r->neg = _a->neg != _b->neg;
	return bnu_trim(r);
}
