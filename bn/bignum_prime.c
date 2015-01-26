#include <bignum.h>
#include "bignum_util.h"
#include <rand.h>

/* runs rabin-miller primality test on the number
 * http://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
 */
int rabin_miller(int *r, const bignum *n, const uint32_t certainty) {
	if(n == NULL) {
		return 1;
	}

	/* get 1 and n - 1 in bignum form for comparison */
	bignum n_minus_one = BN_ZERO;
	if(bno_sub(&n_minus_one, n, &ONE) != 0) {
		return 1;
	}

	/* find n=2^s * d where d is odd */
	/* find the first set bit of a */
	uint64_t i, j;
	for(i = 0; i < n_minus_one.size; i++) {
		for(j = 0; j < 64; j++) {
			if(n_minus_one.d[i] & (1ULL << j)) {
				goto dloopend;
			}
		}
	}
	dloopend:;
	const uint64_t s = i * 64 + j;
	bignum d = BN_ZERO;

	if(bno_rshift(&d, &n_minus_one, s) != 0) {
		return 1;
	}

	bignum a = BN_ZERO;
	bignum x = BN_ZERO;

	/* each iteration has a 1/4 chance of false positive */
	/* run ceil(certainty/2) times to obtain the certainty value*/
	const uint64_t iters = (certainty + 1) / 2;
	for(i = 0; i < iters; i++) {
		if(bni_rand_range(&a, &TWO, &n_minus_one) != 0) {
			return 1;
		}
		if(bno_exp_mod(&x, &a, &d, n) != 0) {
			return 1;
		}

		if(bno_cmp(&x, &ONE) == 0 || bno_cmp(&x, &n_minus_one) == 0) {
			goto testloopend;
		}

		for(j = 0; j < s - 1; j++) {
			if(bno_mul_mod(&x, &x, &x, n) != 0) {
				return 1;
			}
			if(bno_cmp(&x, &one) == 0) {
				*r = 0;
				return 0;
			}
			if(bno_cmp(&x, &n_minus_one) == 0) {
				goto testloopend;
			}
		}
		*r = 0;
		return 0;

		testloopend:;
		//printf("test %llu\n", i);
	}

	bnu_free(&one);
	bnu_free(&two);
	bnu_free(&n_minus_one);
	bnu_free(&d);
	bnu_free(&a);
	bnu_free(&x);

	*r = 1;
	return 0;
}

/* sets r to 1 if probably prime, 0 if definitely composite
 * the odds that this method returns a false positive is at most 2^(-certainty) */
int bnu_probably_prime(int *r, BIGNUM *a, const uint32_t certainty) {
	return 1;
}

int bnu_gen_prime(BIGNUM *r, const int bitlen) {
	return bnu_trim(r);
}

