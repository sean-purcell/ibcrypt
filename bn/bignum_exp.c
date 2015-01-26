#include <stdlib.h>

#include <bignum.h>
#include "bignum_util.h"

/* exponentiation using the montgomery powering ladder
 * http://cr.yp.to/bib/2003/joye-ladder.pdf */
int bno_exp(bignum *r, const bignum *base, const bignum *exp) {
	if(r == NULL || base == NULL || exp == NULL) {
		return -1;
	}

	bignum R[2] = { BN_ZERO, BN_ZERO };

	if(bni_int(&R[0], 1) != 0 || bni_cpy(&R[1], base)) {
		return 1;
	}

	int64_t i;
	for(i = exp->size - 1; i >= 0; i--) {
		int j;
		for(j = 63; j >= 0; j--) {
			uint8_t bit = ((exp->d[i] & ((uint64_t)1 << j)) >> j);
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

int bno_exp_mod(bignum *r, const bignum *base, const bignum *exp, const bignum *n) {
	if(r == NULL || base == NULL || exp == NULL || n == NULL) {
		return -1;
	}

	bignum R[2] = { BN_ZERO, BN_ZERO };
	/* barrett reduction factor */
	bignum m = BN_ZERO;

	if(bni_int(&R[0], 1) != 0) {
		return 1;
	}

	if(bno_rmod(&R[1], base, n) != 0) {
		return 1;
	}

	if(bnu_barrett_mfactor(&m, n) != 0) {
		return 1;
	}

	int64_t i;
	for(i = exp->size - 1; i >= 0; i--) {
		int j;
		for(j = 63; j >= 0; j--) {
			uint8_t bit = ((exp->d[i] & ((uint64_t)1 << j)) >> j);
			if(bno_mul(&R[!bit], &R[0], &R[1]) != 0) {
				return 1;
			}
			if(bno_mul(&R[bit], &R[bit], &R[bit]) != 0) {
				return 1;
			}
			if(bno_barrett_reduce(&R[0], &R[0], &m, n) != 0) {
				return 1;
			}
			if(bno_barrett_reduce(&R[1], &R[1], &m, n) != 0) {
				return 1;
			}
		}
	}

	if(bni_cpy(r, &R[0]) != 0) {
		return 1;
	}

	if(bnu_free(&R[0]) != 0 || bnu_free(&R[1]) != 0 || bnu_free(&m) != 0) {
		return 1;
	}

	return bnu_trim(r);
}

int exp_mod_odd(bignum *r, const bignum *base, const bignum *exp, const bignum *n);

/* copied from java's BigInteger implementation */
int bno_exp_mod_crt(bignum *r, const bignum *base, const bignum *exp, const bignum *n) {
	if(r == NULL || base == NULL || exp == NULL || n == NULL) {
		return -1;
	}

	bignum _n = *n;

	if(_n.size == 0) {
		return 1;
	}

	// odd modulus
	if(_n.d[0] & 1) {

	}

	return 0;
}
