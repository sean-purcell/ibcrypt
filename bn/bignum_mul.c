#include <stdlib.h>
#include <stdint.h>

#include "bignum.h"
#include "bignum_util.h"

int bno_mul_karatsuba(BIGNUM* r, const BIGNUM* _a, const BIGNUM* _b) {
	if(r == NULL || _a == NULL || _b == NULL) {
		return -1;
	}

	uint64_t size = _a->size + _b->size;

	return 0;
}

int bno_mul(BIGNUM* r, const BIGNUM* _a, const BIGNUM* _b) {
	if(r == NULL || _a == NULL || _b == NULL) {
		return -1;
	}

	uint64_t size = _a->size + _b->size;
	if(size > 0xffffffffU) {
		return 2; /* too big */
	}

	BIGNUM a = BN_ZERO;
	BIGNUM b = *_b;
	if(bni_cpy(&a, _a) != 0 || bnu_resize(&a, size + 1) != 0) {
		return 1;
	}

	if(bnu_resize(r, 0) != 0 || bnu_resize(r, size) != 0) {
		return 1;
	}

	uint64_t* const ad = a.d;

	uint32_t i;
	uint64_t lpos = 0;
	for(i = 0; i < b.size; i++) {
		int j;
		for(j = 0; j < 64; j++) {
			/* if bit is set */
			if(b.d[i] & ((uint64_t)1 << j)) {
				lshift_words(ad, ad, _a->size + (lpos + 63)/64, ((uint64_t) i * 64 + j) - lpos);
				add_words(r->d, r->d, size, ad, size);

				lpos = i * 64 + j;
			}
		}
	}

	bnu_free(&a);

	return bnu_trim(r);
}

int bno_mul_mod(BIGNUM* r, const BIGNUM* _a, const BIGNUM* _b, const BIGNUM* const n) {
	if(r == NULL || _a == NULL || _b == NULL || n == NULL) {
		return -1;
	}

	uint64_t size = _a->size + _b->size;
	if(size > 0xffffffffU) {
		return 2; /* too big */
	}

	BIGNUM a = BN_ZERO;
	BIGNUM b = BN_ZERO;
	if(bni_cpy(&a, _a) != 0 || bni_cpy(&b, _b) != 0) {
		return 1;
	}

	if(bno_rmod(&a, &a, n) != 0 || bno_rmod(&b, &b, n) != 0) {
		return 1;
	}

	if(bnu_resize(r, 0) != 0 || bnu_resize(r, n->size+1)) {
		return 1;
	}

	if(bnu_resize(&a, size) != 0) {
		return 1;
	}

	uint64_t* ad = a.d;
	uint64_t* rd = r->d;

	uint32_t i;
	uint64_t lpos = 0;
	for(i = 0; i < b.size; i++) {
		int j;
		for(j = 0; j < 64; j++) {
			/* if bit is set */
			if(b.d[i] & ((uint64_t)1 << j)) {
				lshift_words(ad, ad, n->size, ((uint64_t)i * 64 + j) - lpos);

				rmod_words(ad, size, n);

				int carry = add_words(rd, rd, n->size, ad, n->size);
				rd[n->size] = carry;
				if(cmp_words(rd, n->size+1, n->d, n->size) >= 0) {
					sub_words(rd, rd, n->size+1, n->d, n->size);
				}

				lpos = i * 64 + j;
			}
		}
	}

	bnu_free(&a);
	bnu_free(&b);

	return bnu_trim(r);
}
