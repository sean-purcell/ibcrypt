#include <stdlib.h>
#include <stdint.h>

#include "bignum.h"
#include "bignum_util.h"


void mul_words(uint64_t* const r, uint32_t rlen, uint64_t* const a, uint32_t alen, uint64_t* b, uint32_t blen) {
	/* generic empty vars */
	uint64_t t0, t1;

	uint32_t i, j, k;
	for(i = 0; i < alen; i++) {
		/* split the current a word into two segments */
		const uint64_t aw0 = a[i] & 0xffffffffULL;
		const uint64_t aw1 = a[i] >> 32;

		/* reset the carry */
		uint64_t carry = 0;

		for(j = 0, k = i; j < blen && k < rlen; j++, k++) {
			/* split the current b word into two segments */
			const uint64_t bw0 = b[j] & 0xffffffffULL;
			const uint64_t bw1 = b[j] >> 32;

			/* sp = sub product */
			/* p = product, pwX = product word X */
			/* aw * bw = aw0 * bw0 + (aw0 * bw1 + aw1 * bw0) << 32 + aw1 * bw1 << 64 */
			const uint64_t sp0 = aw0 * bw0;
			const uint64_t sp1 = aw0 * bw1;
			const uint64_t sp2 = aw1 * bw0;
			const uint64_t sp3 = aw1 * bw1;

			/* tmp = sp0 + sp1 << 32 + sp2 << 32 */
			/* pw0 = tmp (lower 64 bits) */
			/* pw1 = sp1 >> 32 + sp2 >> 32 + sp3 + tmp >> 64 */
			t0 = sp0 + (sp1 << 32);
			int prod_carry = t0 < sp0;
			t1 = t0 + (sp2 << 32);
			prod_carry += t1 < t0;
			const uint64_t pw0 = t1;
			const uint64_t pw1 = (sp1 >> 32) + (sp2 >> 32) + sp3 + prod_carry;

			t0 = pw0 + carry;
			carry = t0 < pw0;
			t1 = t0 + r[k];
			carry += t1 < t0;
			r[k] = t1;
			carry += pw1;
		}

		r[k] = carry;
	}
}


// TODO: implement karatsuba multiplication
int bno_mul_karatsuba(BIGNUM* r, const BIGNUM* _a, const BIGNUM* _b) {
	if(r == NULL || _a == NULL || _b == NULL) {
		return -1;
	}

	uint64_t size = _a->size + _b->size;

	return 0;
}

int bno_mul(BIGNUM* _r, const BIGNUM* a, const BIGNUM* b) {
	if(_r == NULL || a == NULL || b == NULL) {
		return -1;
	}

	uint64_t size = a->size + b->size + 1;
	if(size > 0xffffffffULL) {
		return 2; /* too big */
	}

	BIGNUM r = BN_ZERO;
	if(bnu_resize(&r, size) != 0) {
		return 1;
	}

	mul_words(r.d, r.size, a->d, a->size, b->d, b->size);

	if(bnu_trim(&r) != 0 || bnu_free(_r) != 0) {
		return 1;
	}

	*_r = r;
	return 0;
}

int bno_mul_mod(BIGNUM* r, const BIGNUM* _a, const BIGNUM* _b, const BIGNUM* const n) {
	if(bno_mul(r, _a, _b) != 0) {
		return 1;
	}
	return bno_rmod(r, r, n);
}
