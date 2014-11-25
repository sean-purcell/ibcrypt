#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <bignum.h>
#include "bignum_util.h"

/* equivalent to bni_zero(&bn); */
BIGNUM BN_ZERO = {0, 0};

/* create an empty bignum */
int bni_zero(BIGNUM *a) {
	if(a == NULL) {
		return -1;
	}

	a->d = 0;
	a->size = 0;
	return 0;
}

/* create a bignum from the given source */
int bni_int(BIGNUM *a, uint64_t source) {
	if(bni_zero(a) != 0) {
		return -1;
	}

	if(bnu_resize(a, 1) != 0) {
		return 1;
	}

	a->d[0] = source;
	return 0;
}

static inline uint8_t fhex(const char c) {
	if(c <= '9') {
		return (uint8_t) (c - '0');
	} else {
		return (uint8_t) (c - 'a' + 10);
	}
}

/* currently only works with radix 16 */
int bni_fstr(BIGNUM *a, const char *source) {
	if(source == 0) {
		return -1;
	}

	if(bni_zero(a) != 0) {
		return -1;
	}

	const size_t size = strlen(source);
	/* uint32_t max / (bits/char) * length of word */
	if(size > (0xffffffffULL / 4 * 64)) {
		return 2; /* too large */
	}

	                          /* round up */
	if(bnu_resize(a, (uint32_t) ((size + 15) / 16)) != 0) {
		return 1;
	}

	size_t i;
	/* TODO: technically defined but I should rework to not use integer under/overflow later */
	for(i = size-1; (i + 16) >= 16; i -= 16) {
		for(int j = 0; j < 16 && j <= i; j++) {
			a->d[(size-1-i)/16] |= ((uint64_t) fhex(source[i - j])) << (j  *4);
		}
	}

	return 0;
}

int bni_cpy(BIGNUM *r, const BIGNUM *a) {
	if(a == NULL || r == NULL) {
		return -1;
	}

	if(r == a) {
		return 0;
	}

	if(bnu_resize(r, a->size) != 0) {
		return 1;
	}

	memcpy(r->d, a->d, sizeof(uint64_t)  *r->size);

	return 0;
}

/* get 2 to the power of k */
int bni_2power(BIGNUM *_r, const uint64_t k) {
	if(_r == NULL) {
		return -1;
	}

	const uint64_t block = k / 64;
	const uint64_t size = block + 1;
	const uint64_t shift = k % 64;
	if(size > 0xffffffffULL) {
		return 2; /* too big */
	}

	BIGNUM r = BN_ZERO;
	if(bnu_resize(&r, size) != 0) {
		return 1; /* failed to resize */
	}

	r.d[block] = 1ULL << shift;
	*_r = r;

	return 0;
}

