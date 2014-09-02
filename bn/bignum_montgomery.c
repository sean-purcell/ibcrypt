#include "bignum.h"
#include "bignum_util.h"

int montgomery_reduce(BIGNUM* T, const BGINUM* N, const BIGNUM* Nres, const uint64_t R_size) {
	BIGNUM m = BN_ZERO;
	// calculate m:=T(-N^-1) mod R
	if(bno_mul(&m, T, Nres) != 0 || bno_resize(&m, R_size) != 0) {
		return 1;
	}

	// calculate m:=mN
	if(bno_mul(&m, &m, N) != 0) {
		return 1;
	}

	// calculate T:=(T+nM)/R
	if(bno_add(T, T, &m) != 0 || bno_rshift(T, T, R_size * 64) != 0) {
		return 1;
	}

	// if T >= N, return T - N, otherwise return T
	return (bno_cmp(T, N) >= 0 ? bno_sub(T, T, N) : 0);
}

// montgomery multiplication, uses next largest power of 2 as R, therefore only works with odd numbers

int exp_mod_odd(BIGNUM* r, const BIGNUM* base, const BIGNUM* exp, const BIGNUM* n) {
	if(r == 0 || base == 0 || exp == 0 || n == 0) {
		return -1;
	}
	BIGNUM b = *base;

	uint32_t R_exp_words = n->size;

	
}
