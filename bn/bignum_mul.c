#include <stdlib.h>
#include <stdint.h>

#include "bignum.h"
#include "bignum_util.h"

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
			if(b.d[i] & (1ULL << j)) {
				if(bno_lshift(&a, &a, ((uint64_t)i * 64 + j) - lpos) != 0) {
					return 1;
				}

				if(bno_add(r, r, &a) != 0) {
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
