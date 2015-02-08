/* this file should not be released as part of the API,
 * it is purely for internal use */

#ifndef IBCRYPT_BN_BIGNUM_UTIL_H
#define IBCRYPT_BN_BIGNUM_UTIL_H

#include "bignum.h"

#include <stdint.h>

/* some useful constant */
static uint64_t d1 = 1, d2 = 2;

static const bignum ONE  = {&d1, 1};
static const bignum TWO  = {&d2, 1};

int bnu_resize(bignum* r, uint32_t size);

int bnu_trim(bignum* r);

void bno_sub_no_resize(bignum* r, const bignum* a, const bignum* b);
void bno_add_no_resize(bignum* r, const bignum* a, const bignum* b);
int bno_rmod_no_resize(bignum* r, const bignum* n);

/* returns 1 if there was a carry, 0 if not */
int add_words(uint64_t* r, uint64_t* a, const uint32_t alen, uint64_t* b, const uint32_t blen);
/* returns 1 if there was a carry, 0 if not */
int sub_words(uint64_t* r, uint64_t* a, const uint32_t alen, uint64_t* b, const uint32_t blen);

void lshift_words(uint64_t* r, const uint64_t* a, uint32_t a_size, const uint64_t shift);
void rshift_words(uint64_t* r, const uint64_t* a, uint32_t a_size, const uint64_t shift);

int cmp_words(const uint64_t* a, const uint32_t alen, const uint64_t* b, const uint32_t blen);
int rmod_words(uint64_t* r, const uint32_t rlen, const bignum* n);

/* barrett mod reduce operations */
int bno_barrett_reduce(bignum* _r, const bignum* a, const bignum* m, const bignum* n);
int bnu_barrett_mfactor(bignum* r, const bignum* n);

#endif
