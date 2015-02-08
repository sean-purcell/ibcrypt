#ifndef IBCRYPT_BN_BIGNUM_H
#define IBCRYPT_BN_BIGNUM_H

#include <stdint.h>

#define BN_DIG 64

typedef struct bignum_struct {
	uint64_t* d; /* array of 64 bit digits */
	uint32_t size; /* size of d array */
} bignum;

extern bignum BN_ZERO;

/* create an empty bignum */
int bni_zero(bignum* a);

/* create a bignum from the given source */
int bni_int(bignum* a, uint64_t source);

/* currently only works with radix 16 */
int bni_fstr(bignum* a, const char* source);

int bni_cpy(bignum* r, const bignum* a);

int bni_2power(bignum* r, const uint64_t k);

/* returns a random bignum within the range [bot, top) */
int bni_rand_range(bignum* r, const bignum* bot, const bignum* top);

/* returns a random bignum with `bits' bits */
int bni_rand_bits(bignum* r, const uint64_t bits);

/* out must be big enough to hold a */
int bnu_tstr(char* out, const bignum* a);

/* prints a to stdout */
int bnu_print(const bignum* a);

/* frees a bignum, should be used before it goes out of scope */
int bnu_free(bignum* r);

/* + operator */
int bno_add(bignum* r, const bignum* a, const bignum* b);

/* - operator */
int bno_sub(bignum* r, const bignum* a, const bignum* b);

/* * operator */
int bno_mul(bignum* r, const bignum* a, const bignum* b);

/* integer / operator */
int bno_div(bignum* q, const bignum* a, const bignum* b);
/* returns the remainder as well as the quotient */
int bno_div_mod(bignum* q, bignum* r, const bignum* a, const bignum* b);

/* ^ operator */
int bno_exp(bignum* r, const bignum* base, const bignum* exp);

/* % operator */
int bno_rmod(bignum* r, const bignum* a, const bignum* n);

/* return r such that (r + a) == 0 mod n */
int bno_neg_mod(bignum* r, const bignum* a, const bignum* n);

/* return r such that (r*a) == 1 mod n */
int bno_inv_mod(bignum* inv, const bignum* _a, const bignum* _n);

/* barrett reduction functions */
int bnu_barrett_mfactor(bignum* r, const bignum* n);
int bno_barrett_reduce(bignum* _r, const bignum* a, const bignum* m, const bignum* n);

int bno_add_mod(bignum* r, const bignum* a, const bignum* b, const bignum* n);
int bno_mul_mod(bignum* r, const bignum* a, const bignum* b, const bignum* const n);
int bno_exp_mod(bignum* r, const bignum* base, const bignum* exp, const bignum* n);

/* a and r may be the same bignum
 * << operator */
int bno_lshift(bignum* r, const bignum* a, const uint64_t shift);
/* >> operator */
int bno_rshift(bignum* r, const bignum* a, const uint64_t shift);

/* returns 1 if a > b, -1 if a < b, 0 if a == b */
int bno_cmp(const bignum* a, const bignum* b);

/* sets r to 1 if the number is prime with a certainty of at least
 * 1-(2^-certainty), 0 otherwise */
int prime_test(int *r, const bignum *n, const uint32_t certainty);
/* generates a random prime with `bits` bits with certainty `certainty`
 * (see prime_test) */
int bni_rand_prime(bignum *r, const uint64_t bits, const uint32_t certainty);

#endif
