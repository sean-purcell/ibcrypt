#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "bignum.h"
#include "bignum_util.h"

/* bit shifts a given bignum, effectively << and >> operators */

/* a and r may be the same bignum */
int bno_lshift(BIGNUM* r, const BIGNUM* a, uint64_t shift) {
	if(a == NULL || r == NULL) {
		return -1;
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

	const uint32_t blk_shift = shift / 64;
	const uint32_t bit_shift = shift % 64;

	/* now shift each block individually */
	uint32_t i;

	/* amount to shift left by,
	 * amount to shift right by to get the carry */
	const uint8_t lshift = bit_shift;
	const uint8_t rshift = 64 - bit_shift;

	r->d[nsize-1] = rshift == 64 ? 0 : a->d[osize-1] >> rshift;

	/* lshift, OR carry, set new carry, set value */
	for(i = osize-1; i > 0; i--) {
		r->d[i+blk_shift] = (a->d[i] << lshift) | (rshift == 64 ? 0 : a->d[i-1] >> rshift);
	}

	r->d[blk_shift] = a->d[0] << lshift;

	memset(r->d, 0x00, sizeof(uint64_t) * blk_shift);

	return bnu_trim(r);
}

int bno_rshift(BIGNUM* r, const BIGNUM* a, uint64_t shift) {
	if(a == NULL || r == NULL) {
		return -1;
	}

	const uint32_t osize = a->size;
	/* round up */
	const uint32_t nsize = osize - shift / 64;

	/* no bounds check because it only gets smaller */

	/* cant resize yet because they could overlap */

	const uint32_t blk_shift = shift / 64;
	const uint32_t bit_shift = shift % 64;

	/* move blocks */
	memmove(&r->d[0], &a->d[blk_shift], sizeof(uint64_t) * nsize);

	/* no point zeroing, just resize */
	if(bnu_resize(r, nsize) != 0) {
		return 1;
	}

	if(bit_shift == 0) {
		return 0;
	}

	/* now shift block by block */
	uint32_t i;
	uint64_t carry = 0;
	uint64_t t;
	
	/* amount to shift left, right */
	const uint8_t lshift = 64 - bit_shift;
	const uint8_t rshift = bit_shift;

	for(i = nsize - 1; i > 0; i--) {
		t = (r->d[i] >> rshift) | carry;
		carry = r->d[i] << lshift;
		r->d[i] = t;
	}

	r->d[0] = (r->d[0] >> rshift) | carry;

	return bnu_trim(r);
}
