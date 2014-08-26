#include <stdlib.h>

#include "bignum.h"
#include "bignum_util.h"

// don't resize, do inplace
int rmod_words(uint64_t* r, const uint32_t rlen, const BIGNUM* n) {
	BIGNUM nt = BN_ZERO;

	if(bni_cpy(&nt, n) != 0 || bnu_resize(&nt, rlen+1)) {
		return 1;
	}

	uint64_t shift = 0;
	/* shift nt so that its greater than a */
	while(cmp_words(nt.d, nt.size, r, rlen) <= 0) {
		if(bno_lshift(&nt, &nt, 64) != 0) {
			return 1;
		}
//		lshift_words(nt.d, nt.d, 64, nt.size)
		shift += 64;
	}

	for(uint64_t i = 0; i < shift; i++) {
		if(bno_rshift(&nt, &nt, 1) != 0) {
			return 1;
		}
		if(cmp_words(nt.d, nt.size, r, rlen) <= 0) {
			sub_words(r, r, rlen, nt.d, nt.size);
		}
	}

	return 0;
}

int bno_rmod(BIGNUM* r, const BIGNUM* a, const BIGNUM* n) {
	if(r == NULL || a == NULL || n == NULL) {
		return -1;
	}

	if(bno_cmp(a, n) < 0) {
		return bni_cpy(r, a);
	}

	BIGNUM nt = BN_ZERO;
	BIGNUM at = BN_ZERO;
	if(bni_cpy(&nt, n) != 0 || bni_cpy(&at, a) != 0) {
		return 1;
	}

	uint64_t shift = 0;
	/* shift nt so that its greater than a */
	while(bno_cmp(&nt, &at) <= 0) {
		if(bno_lshift(&nt, &nt, 64) != 0) {
			return 1;
		}
		shift += 64;
	}

	for(uint64_t i = 0; i < shift; i++) {
		//if(bno_rshift(&nt, &nt, 1) != 0) {
		//	return 1;
		//}
		rshift_words(nt.d, nt.d, nt.size, 1);
		if(bno_cmp(&nt, &at) <= 0) {
			sub_words(at.d, at.d, at.size, nt.d, nt.size);
			//if(bno_sub(&at, &at, &nt) != 0) {
			//	return 1;
			//}
		}
	}

	if(bni_cpy(r, &at) != 0) {
		return 1;
	}

	bnu_free(&nt);
	bnu_free(&at);

	return bnu_trim(r);
}
