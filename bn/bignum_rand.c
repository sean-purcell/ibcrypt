#include <stdlib.h>

#include "bignum_util.h"
#include <bignum.h>
#include <rand.h>

int bnu_rand(BIGNUM* r, const BIGNUM* bot, const BIGNUM* top) {
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

