#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <bignum.h>
#include "bignum_util.h"

/* words must be at least this size to do karatsuba multiplication */
#define KARATSUBA_THRESHOLD 2

#define max(a, b) ((a) > (b) ? (a) : (b))

void mul_words(uint64_t *const r, uint64_t *const a, uint32_t alen, uint64_t *b, uint32_t blen) {
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

int cross_mul(BIGNUM* _r, const BIGNUM *a, const BIGNUM *b) {
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

int karatsuba_mul(BIGNUM *_r, const BIGNUM *_a, const BIGNUM *_b) {
	/* make a the larger one */
	const BIGNUM *a, *b;
	if(_a->size >= _b->size) {
		a = _a;
		b = _b;
	} else {
		a = _b;
		b = _a;
	}

	if(b->size < KARATSUBA_THRESHOLD) {
		return cross_mul(_r, a, b);
	}

	                          /* round up */
	const uint32_t wordsize = (a->size + 1) / 2;
	if(b->size <= wordsize) {
		/* optimize this later */
		return cross_mul(_r, a, b);
	}

	BIGNUM ah = BN_ZERO,
	       al = BN_ZERO,
	       bh = BN_ZERO,
	       bl = BN_ZERO;
	if(bnu_resize(&al, wordsize) != 0 ||
	   bnu_resize(&bl, wordsize) != 0 ||
	   bnu_resize(&ah, a->size - wordsize) != 0 ||
	   bnu_resize(&bh, b->size - wordsize) != 0) {
		return 1;
	}

	/* copy words into the sections */
	memcpy(al.d, &a->d[0], al.size * sizeof(uint64_t));
	memcpy(bl.d, &b->d[0], bl.size * sizeof(uint64_t));
	memcpy(ah.d, &a->d[wordsize], ah.size * sizeof(uint64_t));
	memcpy(bh.d, &b->d[wordsize], bh.size * sizeof(uint64_t));

	BIGNUM t1 = BN_ZERO,
	       t2 = BN_ZERO,
	       t3 = BN_ZERO,
	       r  = BN_ZERO;
	if(bnu_resize(&r, a->size + b->size) != 0) {
		return 1;
	}

	/* compute al*bl and ah*bh */
	if(cross_mul(&t1, &al, &bl) != 0 || cross_mul(&t2, &ah, &bh) != 0) {
		return 1;
	}

	/* copy in al*bl and ah*bh */
	memcpy(&r.d[0], t1.d, t1.size * sizeof(uint64_t));
	memcpy(&r.d[2 * wordsize], t2.d, t2.size * sizeof(uint64_t));

	/* subtract al*bl and ah*bh from the middle */
	sub_words(&r.d[wordsize], &r.d[wordsize], r.size - wordsize, t1.d, t1.size);
	sub_words(&r.d[wordsize], &r.d[wordsize], r.size - wordsize, t2.d, t2.size);

	/* calculate al+ah and bl+bh */
	if(bno_add(&t1, &al, &ah) != 0 || bno_add(&t2, &bl, &bh) != 0) {
		return 1;
	}

	/* calculate (al+ah)(bl+bh) */
	if(cross_mul(&t3, &t1, &t2) != 0) {
		return 1;
	}

	add_words(&r.d[wordsize], &r.d[wordsize], r.size - wordsize, t3.d, t3.size);

	if(bnu_trim(&r) != 0 || bnu_free(_r) != 0) {
		return 1;
	}

	*_r = r;

	return bnu_free(&ah) || bnu_free(&al) || bnu_free(&bh) || bnu_free(&bl) ||
	       bnu_free(&t1) || bnu_free(&t2) || bnu_free(&t3);
}

int bno_mul(BIGNUM *_r, const BIGNUM *a, const BIGNUM *b) {
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

int bno_mul_mod(BIGNUM *r, const BIGNUM *_a, const BIGNUM *_b, const BIGNUM *const n) {
	if(bno_mul(r, _a, _b) != 0) {
		return 1;
	}
	return bno_rmod(r, r, n);
}

