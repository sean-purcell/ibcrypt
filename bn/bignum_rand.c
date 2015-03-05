#include <stdlib.h>

#include <libibur/util.h>

#include "bignum_util.h"
#include "bignum.h"
#include "../misc/rand.h"

int bni_rand_bits(bignum *r, const uint64_t bits) {
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

int bni_rand_range(bignum *r, const bignum *bot, const bignum *top) {
	if(r == NULL || bot == NULL || top == NULL) {
		return 1;
	}

	bignum range = BN_ZERO;

	if(bno_sub(&range, top, bot) != 0) {
		return 1;
	}

	if(bnu_free(r) != 0 || bnu_resize(r, range.size)) {
		return 1;
	}

	uint64_t mask = ((uint64_t)2 << lg(range.d[range.size - 1])) - 1;

	do {
		cs_rand(r->d, r->size * sizeof(uint64_t));
		r->d[r->size - 1] &= mask;
	} while(bno_cmp(r, &range) >= 0);

	if(bno_add(r, r, bot) != 0) {
		return 1;
	}

	return bnu_free(&range) != 0 || bnu_trim(r);
}

