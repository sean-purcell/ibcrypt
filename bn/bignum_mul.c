#include <stdlib.h>
#include <stdint.h>

#include "bignum.h"

static int mulbuffers(BIGNUM* r, const BIGNUM* _a, const BIGNUM* b) {
	int cmp = bno_ucmp(_a, b);
	if(cmp == -1) {
		const BIGNUM* tmp = _a;
		_a = b;
		b = tmp;
	}

	BIGNUM a;
	if(bni_cpy(&a, _a) != 0) {
		return 1;
	}

	uint32_t i;
	uint64_t lpos = 0;
	for(i = 0; i < b->size; i++) {
		
	}
}

int bno_mul(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	if(r == NULL || a == NULL || b == NULL) {
		return -1;
	}

	uint64_t size = a->size * b->size;
	if(size > 0xffffffffU) {
		return 2; /* too big */
	}

	if(resize(r, (uint32_t) size) != 0) {
		return 1;
	}
}
