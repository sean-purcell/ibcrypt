#include <bignum.h>
#include "bignum_util.h"

int montgomery_reduce(BIGNUM* T, const BIGNUM* N, const BIGNUM* Nres, const uint32_t R_size) {
	BIGNUM m = BN_ZERO;
	// calculate m:=T(-N^-1) mod R
	if(bno_mul(&m, T, Nres) != 0 || bnu_resize(&m, R_size) != 0) {
		return 1;
	}

	// calculate m:=mN
	if(bno_mul(&m, &m, N) != 0) {
		return 1;
	}

	// calculate T:=(T+mN)/R
	if(bno_add(T, T, &m) != 0 || bno_rshift(T, T, R_size * 64) != 0) {
		return 1;
	}

	if(bnu_free(&m) != 0) {
		return 1;
	}

	// if T >= N, return T - N, otherwise return T
	return (bno_cmp(T, N) >= 0 ? bno_sub(T, T, N) : 0);
}

int montgomery_mul(BIGNUM* res, const BIGNUM* a, const BIGNUM* b, const BIGNUM* N, const BIGNUM* Nres, const uint32_t R_size) {
	return bno_mul(res, a, b) != 0 || montgomery_reduce(res, N, Nres, R_size) != 0;
}

int montgomery_step(BIGNUM* res, const BIGNUM* a, const BIGNUM* b, const uint64_t R_bits) {
	return bno_mul(res, a, b) != 0 || bno_rshift(res, res, R_bits) != 0;
}

// montgomery multiplication, uses next largest power of 2 as R, therefore only works with odd numbers

int exp_mod_odd(BIGNUM* r, const BIGNUM* base, const BIGNUM* exp, const BIGNUM* n) {
	if(r == 0 || base == 0 || exp == 0 || n == 0) {
		return -1;
	}
	BIGNUM b = *base;

	const uint32_t R_exp_words = n->size;
	const uint64_t R_bits = R_exp_words * 64;

	BIGNUM R = BN_ZERO, Nres = BN_ZERO;

	/* create R */
	if(bnu_resize(&R, R_exp_words+1) != 0) {
		return 1;
	}
	R.d[R_exp_words] = 1;

	/* pre calculate -N^-1 mod R */
	if(bno_inv_mod(&Nres, n, &R) != 0 || bno_neg_mod(&Nres, &Nres, &R)) {
		return 1;
	}

	BIGNUM A[2] = { BN_ZERO, BN_ZERO };

	if(bni_fstr(&A[0], "1") != 0) {
		return 1;
	}

	if(bno_rmod(&A[1], base, n) != 0) {
		return 1;
	}

	if(bno_lshift(&A[1], &A[1], R_bits) != 0 || bno_rmod(&A[1], &A[1], n) != 0) {
		return 1;
	}

	int64_t i;
	for(i = exp->size - 1; i >= 0; i--) {
		int j;
		for(j = 63; j >= 0; j--) {
			uint8_t bit = ((exp->d[i] & ((uint64_t)1 << j)) >> j);
			if(montgomery_step(&A[!bit], &A[0], &A[1], R_bits) != 0) {
				return 1;
			}
			if(montgomery_step(&A[bit], &A[bit], &A[bit], R_bits) != 0) {
				return 1;
			}
		}
	}

	if(bni_cpy(r, &A[0]) != 0) {
		return 1;
	}
	montgomery_reduce(r, n, &Nres, R_exp_words);

	bnu_free(&A[0]);
	bnu_free(&A[1]);

	return bnu_trim(r);
}
