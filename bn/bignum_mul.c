#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "bignum.h"
#include "bignum_util.h"

/* words must be at least this size to do karatsuba multiplication */
#define KARATSUBA_THRESHOLD 4

#define max(a, b) ((a) > (b) ? (a) : (b))

void mul_words(uint64_t* const r, uint64_t* const a, uint32_t alen, uint64_t* b, uint32_t blen) {
	/* generic empty vars */
	uint64_t t0, t1;

	uint32_t i, j, k;
	for(i = 0; i < alen; i++) {
		/* split the current a word into two segments */
		const uint64_t aw0 = a[i] & 0xffffffffULL;
		const uint64_t aw1 = a[i] >> 32;

		/* reset the carry */
		uint64_t carry = 0;

		for(j = 0, k = i; j < blen; j++, k++) {
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

/* scratch must point to a region of read-write space free for use of size
 * greater than or equal to wsize * 4 */
void mul_words_karatsuba(uint64_t* const r, uint64_t* const a, uint32_t alen, uint64_t* const b, uint32_t blen, uint64_t* const scratch) {
	/* if it's too small, switch to regular (recursion base case) */
	if(alen < KARATSUBA_THRESHOLD || blen < KARATSUBA_THRESHOLD) {
		mul_words(r, a, alen, b, blen);
		return;
	}

	const uint32_t rsize = alen + blen;
	const uint32_t maxsize = max(alen, blen);
	/* round up */
	const uint32_t wsize = (maxsize + 1) / 2;

	if(alen < wsize || blen < wsize) {
		mul_words(r, a, alen, b, blen);
		return;
	}

	uint64_t* const a0 = a;
	uint64_t* const b0 = b;
	uint64_t* const a1 = &a[wsize];
	uint64_t* const b1 = &b[wsize];
	const uint32_t a1len = alen - wsize;
	const uint32_t b1len = blen - wsize;

	/* add_words carries */
	int carry;
	/* zero memory out
	 * 1 word size for each sum
	 * 2 word sizes for the scratch space */
	memset(scratch, 0, 5 * wsize * sizeof(uint64_t));
	/* effect (a0+a1)(b0+b1) */
	carry = add_words(scratch, a0, wsize, a1, a1len);
	scratch[wsize] = carry;
	carry = add_words(&scratch[wsize+1], b0, wsize, b1, b1len);
	scratch[2 * wsize + 1] = carry;
	mul_words_karatsuba(&r[wsize], scratch, wsize+1, &scratch[wsize+1], wsize+1, &scratch[2 * wsize + 2]);

	/* zero memory out
	 * 2 word sizes for the product
	 * 2 word sizes for the scratch space */
	memset(scratch, 0, 5 * wsize * sizeof(uint64_t));
	/* effect a0*b0 */
	mul_words_karatsuba(scratch, a0, wsize, b0, wsize, &scratch[2 * wsize]);
	/* start adding them to r */
	add_words(r, r, rsize, scratch, 2 * wsize);
	sub_words(&r[wsize], &r[wsize], rsize - wsize, scratch, 2 * wsize);

	/* zero memory out
	 * 2 word sizes for the product
	 * 2 word sizes for the scratch space */
	memset(scratch, 0, 5 * wsize * sizeof(uint64_t));
	/* effect a0*b0 */
	mul_words_karatsuba(scratch, a1, a1len, b1, b1len, &scratch[2 * wsize]);
	/* start adding them to r */
	add_words(&r[2 * wsize], &r[2 * wsize], rsize - 2 * wsize, scratch, a1len + b1len);
	sub_words(&r[wsize], &r[wsize], rsize - wsize, scratch, a1len + b1len);
}

int bno_mul_karatsuba(BIGNUM* _r, const BIGNUM* a, const BIGNUM* b) {
	if(_r == NULL || a == NULL || b == NULL) {
		return -1;
	}

	uint64_t size = (uint64_t) a->size + b->size;
	if(size > 0xffffffffULL) {
		return 2; /* too big */
	}
	uint64_t wsize = (max(a->size, b->size) + 1) / 2;
	uint64_t scratch_size = wsize * 20;
	if(scratch_size > 0xffffffffULL) {
		return 2; /* too big */
	}

	BIGNUM r = BN_ZERO;
	BIGNUM scratch = BN_ZERO;
	if(bnu_resize(&r, size) != 0) {
		return 1;
	}
	if(bnu_resize(&scratch, scratch_size) != 0) {
		return 1;
	}

	mul_words_karatsuba(r.d, a->d, a->size, b->d, b->size, scratch.d);

	if(bnu_trim(&r) != 0 || bnu_free(_r) != 0 || bnu_free(&scratch) != 0) {
		return 1;
	}

	*_r = r;
	return 0;
}

int bno_mul(BIGNUM* _r, const BIGNUM* a, const BIGNUM* b) {
	if(_r == NULL || a == NULL || b == NULL) {
		return -1;
	}

	uint64_t size = (uint64_t) a->size + b->size;
	if(size > 0xffffffffULL) {
		return 2; /* too big */
	}

	BIGNUM r = BN_ZERO;
	if(bnu_resize(&r, size) != 0) {
		return 1;
	}

	mul_words(r.d, a->d, a->size, b->d, b->size);

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
