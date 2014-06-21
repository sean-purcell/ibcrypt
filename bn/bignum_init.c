#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bignum.h"
#include "bignum_util.h"

BIGNUM BN_ZERO = {0, 0, 0};

/* create an empty bignum */
int bni_zero(BIGNUM* a) {
	if(a == NULL) {
		return -1;
	}

	a->d = 0;
	a->size = 0;
	a->neg = 0;
	return 0;
}

/* create a bignum from the given source */
int bni_uint(BIGNUM* a, uint64_t source) {
	if(bni_zero(a) != 0) {
		return -1;
	}

	if(bnu_resize(a, 1) != 0) {
		return 1;
	}

	a->d[0] = source;
	return 0;
}

int bni_int(BIGNUM* a, int64_t source) {
	int rc;
	int neg = source < 0 ? 1 : 0;
	if((rc = bni_uint(a, neg ? -source : source)) != 0) {
		return rc;
	}

	a->neg = 1;
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
int bni_fstr(BIGNUM* a, const char* source) {
	if(source == 0) {
		return -1;
	}

	if(bni_zero(a) != 0) {
		return -1;
	}

	if(source[0] == '-') {
		a->neg = 1;
		source++;
	}

	const size_t size = strlen(source);
	if(size > (0xffffffffULL * 16) /* uint32_t max */) {
		return 2; /* too large */
	}

	                          /* round up */
	bnu_resize(a, (uint32_t) ((size + 15) / 16));

	size_t i;
	/* TODO: technically defined but I should rework to not use integer under/overflow later */
	for(i = size-1; (i + 16) >= 16; i -= 16) {
		for(int j = 0; j < 16 && j <= i; j++) {
			a->d[(size-1-i)/16] |= ((uint64_t) fhex(source[i - j])) << (j * 4);
		}
	}

	return 0;
}

int bni_cpy(BIGNUM* r, const BIGNUM* a) {
	if(a == NULL || r == NULL) {
		return -1;
	}

	bnu_resize(r, a->size);
	r->neg = a->neg;

	memcpy(r->d, a->d, sizeof(uint64_t) * r->size);

	return 0;
}
