#include <stdlib.h>

#include "bignum_util.h"
#include <bignum.h>
#include <rand.h>

int bni_rand_bits(BIGNUM* r, const uint64_t bits) {
	if(r == NULL) {
		return 1;
	}

	if(bits / 64 > 0xffffffffULL) {
		return 2; /* too big */
	}

	const uint32_t size = (bits + 63) / 64;
	if(bnu_resize(r, size) != 0) {
		return 1;
	}

	if(cs_rand(&r->d[0], sizeof(uint64_t) * size) != 0) {
		return 1;
	}

	if(bits % 64 != 0) {
		uint64_t mask = (1ULL << (bits % 64)) - 1;
		r->d[size - 1] &= mask;
	}

	return 0;
}

int bni_rand_range(BIGNUM* r, const BIGNUM* bot, const BIGNUM* top) {
	if(r == NULL || bot == NULL || top == NULL) {
		return 1;
	}

	BIGNUM range = BN_ZERO;

	if(bno_sub(&range, top, bot) != 0) {
		return 1;
	}

	if(bnu_free(r) != 0 || bnu_resize(r, top->size)) {
		return 1;
	}

	uint32_t topword = range.size - 1;
	if(cs_rand_uint64_range(&r->d[topword], range.d[topword]) != 0) {
		return 1;
	}

	if(cs_rand(&r->d[0], sizeof(uint64_t) * topword) != 0) {
		return 1;
	}

	add_words(r->d, r->d, top->size, bot->d, bot->size);

	return bnu_free(&range) != 0 || bnu_trim(r);
}

