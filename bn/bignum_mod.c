#include <stdlib.h>

#include "bignum.h"
#include "bignum_util.h"

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

	uint32_t msb = 63;
	while(!(nt.d[nt.size-1] & (1 << msb))) {msb++;}

	const uint64_t shift = (uint64_t)at.size * 64 - (uint64_t)(nt.size-1) * 64 + msb;
	/* shift nt so that the most significant 1 bit is at the top of the array */
	if(bno_lshift(&nt, &nt, shift) != 0) {
		return 1;
	}

	for(uint64_t i = 0; i < shift; i++) {
		if(bno_ucmp(&nt, &at) < 0) {
			if(bno_usub(&at, &at, &nt) != 0) {
				return 1;
			}
		}
		if(bno_rshift(&nt, &nt, 1) != 0) {
			return 1;
		}
	}

	if(bni_cpy(r, &at) != 0) {
		return 1;
	}

	bnu_free(&nt);
	bnu_free(&at);

	return bnu_trim(r);
}
