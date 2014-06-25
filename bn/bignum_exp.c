#include "bignum.h"
#include "bignum_util.h"

int bno_exp(BIGNUM* r, const BIGNUM* base, const BIGNUM* exp) {
	if(r == 0 || base == 0 || exp == 0) {
		return -1;
	}

	BIGNUM R[2] = { BN_ZERO, BN_ZERO };

	if(bni_fstr(&R[0], "1") != 0 || bni_cpy(&R[1], base)) {
		return 1;
	}

	int64_t i;
	for(i = exp->size - 1; i >= 0; i--) {
		int j;
		for(j = 63; j >= 0; j--) {
			uint8_t bit = ((exp->d[i] & (1 << j)) >> j);
			if(bno_mul(&R[!bit], &R[0], &R[1]) != 0) {
				return 1;
			}
			if(bno_mul(&R[bit], &R[bit], &R[bit]) != 0) {
				return 1;
			}
		}
	}

	if(bni_cpy(r, &R[0]) != 0) {
		return 1;
	}

	bnu_free(&R[0]);
	bnu_free(&R[1]);

	return bnu_trim(r);
}
