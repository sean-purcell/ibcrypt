#include <stdlib.h>
#include <string.h>

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
	const uint64_t nsize = osize + (shift + 63) / 64;
	if(nsize > 0xffffffff) {
		return 2; /* too big */
	}

	if(bnu_resize(r, (uint32_t) nsize) != 0) {
		return 1; /* resize failed */
	}

	const uint32_t blk_shift = shift / 64;
	const uint32_t bit_shift = shift % 64;

	/* move the numbers block by block to the extent that we can */
	/* note: must be block by block not byte by byte due to endian-ness */
	/* TODO: check parameters to memove, make sure it can handle this */
	memmove(&r->d[blk_shift], &a->d[0], sizeof(uint64_t) * osize);
	/* zero introduced space at LS side */
	memset(&r->d[0], 0x00, sizeof(uint64_t) * blk_shift);

	/* TODO: point of concern: this is not constant time */
	/* if there is no bitshift we are done */
	if(bit_shift == 0) {
		return 0;
	}

	/* now shift each block individually */
	uint32_t i;
	uint64_t carry = 0;
	uint64_t t;

	/* amount to shift left by,
	 * amount to shift right by to get the carry */
	const uint8_t lshift = bit_shift;
	const uint8_t rshift = 64 - bit_shift;

	/* lshift, OR carry, set new carry, set value */
	for(i = blk_shift; i < nsize - 1; i++) {
		t = (r->d[i] << lshift) | carry;
		carry = r->d[i] >> rshift;
		r->d[i] = t;
	}

	r->d[nsize - 1] = carry;

	return bnu_trim(r);
}
