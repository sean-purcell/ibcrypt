#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "bignum.h"
#include "bignum_util.h"

/* shift the actual words, no resizing or checks etc. */
void lshift_words(uint64_t* r, const uint64_t* a, uint32_t a_size, const uint64_t shift) {
	if(a_size == 0) return;
	const uint32_t osize = a_size;
	/* round up */
	const uint64_t nsize = osize + (shift+63) / 64;

	const uint32_t blk_shift = shift / 64;
	const uint32_t bit_shift = shift % 64;

	/* now shift each block individually */
	uint32_t i;

	/* amount to shift left by,
	 * amount to shift right by to get the carry */
	const uint8_t lshift = bit_shift;
	const uint8_t rshift = 64 - bit_shift;

	if(rshift != 64) {
		r[nsize-1] = a[osize-1] >> rshift;
	}

	/* lshift, OR carry, set new carry, set value */
	for(i = osize-1; i > 0; i--) {
		r[i+blk_shift] = (a[i] << lshift) | (rshift == 64 ? 0 : a[i-1] >> rshift);
	}

	r[blk_shift] = a[0] << lshift;

	memset(r, 0x00, sizeof(uint64_t) * blk_shift);
}

void rshift_words(uint64_t* r, const uint64_t* a, uint32_t a_size, const uint64_t shift) {
	if(a_size == 0) return;
	const uint32_t blk_shift = shift / 64;
	const uint32_t bit_shift = shift % 64;

	const uint32_t osize = a_size;
	/* round up */
	const uint32_t nsize = osize - blk_shift;

	/* no bounds check because it only gets smaller */

	/* cant resize yet because they could overlap */

	/* now shift block by block */
	uint32_t i;

	/* amount to shift left, right */
	const uint8_t lshift = 64 - bit_shift;
	const uint8_t rshift = bit_shift;

	for(i = blk_shift; i < osize-1; i++) {
		r[i-blk_shift] = (a[i] >> rshift) | (lshift == 64 ? 0 : a[i+1] << lshift);
	}
	r[osize-1-blk_shift] = a[osize-1] >> rshift;

	memset(&r[nsize], 0x00, sizeof(uint64_t) * blk_shift);
}

/* bit shifts a given bignum, effectively << and >> operators */

/* a and r may be the same bignum */
int bno_lshift(BIGNUM* r, const BIGNUM* a, const uint64_t shift) {
	if(a == NULL || r == NULL) {
		return -1;
	}

	if(a->size == 0) {
		return bnu_resize(r, 0);
	}

	const uint32_t osize = a->size;
	/* round up */
	const uint64_t nsize = osize + shift / 64 + 1;
	if(nsize > 0xffffffff) {
		return 2; /* too big */
	}

	if(bnu_resize(r, (uint32_t) nsize) != 0) {
		return 1; /* resize failed */
	}

	lshift_words(r->d, a->d, osize, shift);

	return bnu_trim(r);
}

int bno_rshift(BIGNUM* r, const BIGNUM* a, const uint64_t shift) {
	if(a == NULL || r == NULL) {
		return -1;
	}

	const uint32_t blk_shift = shift / 64;

	if(a->size <= blk_shift) {
		return bnu_resize(r, 0);
	}

	rshift_words(r->d, a->d, a->size, shift);

	return bnu_trim(r);
}
