#ifndef IBCRYPT_BN_BIGNUM_H
#define IBCRYPT_BN_BIGNUM_H

#include <stdint.h>

#define BN_DIG 64

typedef struct bignum_struct {
	uint64_t* d; /* array of 64 bit digits */
	uint32_t size; /* size of d array */
	int neg; /* negative flag */
} BIGNUM;

extern BIGNUM BN_ZERO;

/* create an empty bignum */
int bni_zero(BIGNUM* a);

/* create a bignum from the given source */
int bni_uint(BIGNUM* a, uint64_t source);
int bni_int(BIGNUM* a, int64_t source);

/* currently only works with radix 16 */
int bni_fstr(BIGNUM* a, const char* source);

int bni_cpy(BIGNUM* r, const BIGNUM* a);

/* out must be big enough to hold a */
int bnu_tstr(char* out, const BIGNUM* a);

/* frees a bignum, should be used before it goes out of scope */
int bnu_free(BIGNUM* r);

int bno_uadd(BIGNUM* r, const BIGNUM* a, const BIGNUM* b);
int bno_usub(BIGNUM* r, const BIGNUM* a, const BIGNUM* b);
/* + operator */
int bno_add(BIGNUM* r, const BIGNUM* a, const BIGNUM* b);

/* * operator */
int bno_mul(BIGNUM* r, const BIGNUM* a, const BIGNUM* b);

/* ^ operator */
int bno_exp(BIGNUM* r, const BIGNUM* base, const BIGNUM* exp);

/* a and r may be the same bignum
 * << operator */
int bno_lshift(BIGNUM* r, const BIGNUM* a, uint64_t shift);
/* >> operator */
int bno_rshift(BIGNUM* r, const BIGNUM* a, uint64_t shift);

/* returns 1 if a > b, -1 if a < b, 0 if a == b
 * ignores sign */
int bno_ucmp(const BIGNUM* a, const BIGNUM* b);
/* returns 1 if a > b, -1 if a < b, 0 if a == b */
int bno_cmp(const BIGNUM* a, const BIGNUM* b);

#endif
