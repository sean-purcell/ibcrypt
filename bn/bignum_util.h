/* this file should not be released as part of the API,
 * it is purely for internal use */

#ifndef IBCRYPT_BN_BIGNUM_UTIL_H
#define IBCRYPT_BN_BIGNUM_UTIL_H

#include <stdint.h>

int bnu_resize(BIGNUM* r, uint32_t size);

int bnu_trim(BIGNUM* r);

void bno_sub_no_resize(BIGNUM* r, const BIGNUM* a, const BIGNUM* b);
void bno_add_no_resize(BIGNUM* r, const BIGNUM* a, const BIGNUM* b);
int bno_rmod_no_resize(BIGNUM* r, const BIGNUM* n);

/* returns 1 if there was a carry, 0 if not */
int add_words(uint64_t* r, uint64_t* a, uint32_t alen, uint64_t* b, uint32_t blen);
/* returns 1 if there was a carry, 0 if not */
int sub_words(uint64_t* r, uint64_t* a, uint32_t alen, uint64_t* b, uint32_t blen);

#endif
