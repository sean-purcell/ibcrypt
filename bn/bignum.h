#ifndef IBCRYPT_BN_BIGNUM_H
#define IBCRYPT_BN_BIGNUM_H

#include <stdint.h>

#define BN_DIG 64

typedef struct bignum_struct {
	uint64_t* d; /* array of 64 bit digits */
	uint32_t size; /* size of d array */
} BIGNUM;

extern BIGNUM BN_ZERO;

/* create an empty bignum */
int bni_zero(BIGNUM* a);

/* create a bignum from the given source */
int bni_int(BIGNUM* a, uint64_t source);

/* currently only works with radix 16 */
int bni_fstr(BIGNUM* a, const char* source);

int bni_cpy(BIGNUM* r, const BIGNUM* a);

/* out must be big enough to hold a */
int bnu_tstr(char* out, const BIGNUM* a);

/* frees a bignum, should be used before it goes out of scope */
int bnu_free(BIGNUM* r);

/* + operator */
int bno_add(BIGNUM* r, const BIGNUM* a, const BIGNUM* b);

/* - operator */
int bno_sub(BIGNUM* r, const BIGNUM* a, const BIGNUM* b);

/* * operator */
int bno_mul(BIGNUM* r, const BIGNUM* a, const BIGNUM* b);

/* integer / operator */
int bno_div(BIGNUM* q, const BIGNUM* a, const BIGNUM* b);
/* returns the remainder as well as the quotient */
int bno_div_mod(BIGNUM* q, BIGNUM* r, const BIGNUM* a, const BIGNUM* b);

/* ^ operator */
int bno_exp(BIGNUM* r, const BIGNUM* base, const BIGNUM* exp);

/* % operator */
int bno_rmod(BIGNUM* r, const BIGNUM* a, const BIGNUM* n);

/* return r such that (r + a) == 0 mod n */
int bno_neg_mod(BIGNUM* r, const BIGNUM* a, const BIGNUM* n);

/* return r such that (r*a) == 1 mod n */
int bno_inv_mod(BIGNUM* inv, const BIGNUM* _a, const BIGNUM* _n);

/* barrett reduction functions */
int bnu_barrett_mfactor(BIGNUM* r, const BIGNUM* n);
int bno_barrett_reduce(BIGNUM* _r, const BIGNUM* a, const BIGNUM* m, const BIGNUM* n);

int bno_add_mod(BIGNUM* r, const BIGNUM* a, const BIGNUM* b, const BIGNUM* n);
int bno_mul_mod(BIGNUM* r, const BIGNUM* a, const BIGNUM* b, const BIGNUM* const n);
int bno_exp_mod(BIGNUM* r, const BIGNUM* base, const BIGNUM* exp, const BIGNUM* n);

/* a and r may be the same bignum
 * << operator */
int bno_lshift(BIGNUM* r, const BIGNUM* a, const uint64_t shift);
/* >> operator */
int bno_rshift(BIGNUM* r, const BIGNUM* a, const uint64_t shift);

/* returns 1 if a > b, -1 if a < b, 0 if a == b */
int bno_cmp(const BIGNUM* a, const BIGNUM* b);

#endif
