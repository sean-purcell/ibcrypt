#include <stdlib.h>

#include "bignum.h"
#include "bignum_util.h"

// don't resize, do inplace
int bno_rmod_no_resize(BIGNUM* r, const BIGNUM* n) {
	BIGNUM nt = BN_ZERO;

	if(bni_cpy(&nt, n) != 0) {
		return 1;
	}

	uint64_t shift = 0;
	/* shift nt so that its greater than a */
	while(bno_ucmp(&nt, r) <= 0) {
		if(bno_lshift(&nt, &nt, 32) != 0) {
			return 1;
		}
		shift += 32;
	}

	for(uint64_t i = 0; i < shift; i++) {
		if(bno_rshift(&nt, &nt, 1) != 0) {
			return 1;
		}
		if(bno_ucmp(&nt, r) <= 0) {
			bno_usub_no_resize(r, r, &nt);
		}
	}
}

int bno_rmod(BIGNUM* r, const BIGNUM* a, const BIGNUM* n) {
	if(r == NULL || a == NULL || n == NULL) {
		return -1;
	}

	if(bno_ucmp(a, n) < 0) {
		return bni_cpy(r, a);
	}

	BIGNUM nt = BN_ZERO;
	BIGNUM at = BN_ZERO;
	if(bni_cpy(&nt, n) != 0 || bni_cpy(&at, a) != 0) {
		return 1;
	}

	uint64_t shift = 0;
	/* shift nt so that its greater than a */
	while(bno_ucmp(&nt, &at) <= 0) {
		if(bno_lshift(&nt, &nt, 32) != 0) {
			return 1;
		}
		shift += 32;
	}

	for(uint64_t i = 0; i < shift; i++) {
		if(bno_rshift(&nt, &nt, 1) != 0) {
			return 1;
		}
		if(bno_ucmp(&nt, &at) <= 0) {
			if(bno_usub(&at, &at, &nt) != 0) {
				return 1;
			}
		}
	}

	if(bni_cpy(r, &at) != 0) {
		return 1;
	}

	bnu_free(&nt);
	bnu_free(&at);

	return bnu_trim(r);
}

