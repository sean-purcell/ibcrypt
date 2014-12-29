#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libibur/util.h>

#include <bignum.h>
#include "bignum_util.h"

/* words must be at least this size to do karatsuba multiplication */
#define KARATSUBA_THRESHOLD 1

#undef max
#define max(a, b) ((a) > (b) ? (a) : (b))

void x_mul_words(uint64_t *const r, uint64_t *const a, uint32_t alen, uint64_t *b, uint32_t blen) {
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

void k_mul_words(uint64_t *const r, uint64_t *const _a, uint32_t _alen, uint64_t *const _b, uint32_t _blen, uint64_t *const scratch) {
	uint64_t *a, *b;
	uint32_t alen, blen;
	if(_alen >= _blen) {
		a = _a;
		b = _b;
		alen = _alen;
		blen = _blen;
	} else {
		a = _b;
		b = _a;
		alen = _blen;
		blen = _alen;
	}

	if(blen <= KARATSUBA_THRESHOLD) {
		x_mul_words(r, a, alen, b, blen);
		return;
	}

	const uint32_t rsize = alen + blen;
	const uint32_t wsize = (alen + 1)/2;
	if(blen <= wsize) {
		/* optimize this later */
		x_mul_words(r, a, alen, b, blen);
		return;
	}

	uint64_t *al, *ah, *bl, *bh;
	al = &a[0];
	ah = &a[wsize];
	bl = &b[0];
	bh = &b[wsize];

	/* zero out scratch space and result space */
	memset(scratch, 0x00, (2 * wsize + 2) * sizeof(uint64_t));
	memset(      r, 0x00,           rsize * sizeof(uint64_t));

	uint64_t *t1, *t2, *t3;
	t1 = &scratch[0]; /* wsize + 1 wide */
	t2 = &scratch[wsize + 1]; /* wsize + 1 wide */
	t3 = &scratch[2 * wsize + 2]; /* rest of the scratch space */

	/* calculate ah+al and bh+bl */
	int carry;
	carry = add_words(t1, ah, alen - wsize, al, wsize);
	t1[wsize] = carry;
	carry = add_words(t2, bh, blen - wsize, bl, wsize);
	t2[wsize] = carry;

	/* calculate (ah+al)(bh+bl) into the result space */
	x_mul_words(&r[wsize], t1, wsize + 1, t2, wsize + 1);

	/* calculate al * bl */
	x_mul_words(t1, al, wsize, bl, wsize);
	add_words(&r[    0], &r[    0],         rsize, t1, 2 * wsize);
	sub_words(&r[wsize], &r[wsize], rsize - wsize, t1, 2 * wsize);

	/* calculate ah * bh */
	x_mul_words(t1, ah, alen - wsize, bh, blen - wsize);
	add_words(&r[2 * wsize], &r[2 * wsize], rsize - 2 * wsize, t1, rsize - 2 * wsize);
	sub_words(&r[    wsize], &r[    wsize], rsize -     wsize, t1, rsize - 2 * wsize);

	/* done */
}

uint32_t k_scratch_req(const uint32_t size) {
	const uint32_t RECURSION_CUTOFF = 1024;
	if(size <= RECURSION_CUTOFF) {
		if(size <= 3) {
			return 0;
		} else {
			return 2 * ((size+1)/2) + 2
			                     /* wsize + 1 */
				+ k_scratch_req((size+1)/2 + 1);
		}
	} else {
		return 2 * size + 8 * lg(size - 4) - 10;
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

	x_mul_words(r.d, a->d, a->size, b->d, b->size);

	if(bnu_trim(&r) != 0 || bnu_free(_r) != 0) {
		return 1;
	}

	*_r = r;
	return 0;
}

/*
 * a   = (ah*B + al)
 * b   = (bh*B + bl)
 * a*b = (ah*B + al)(bh*B + bl)
 * a*b = ah*bh*B^2 + (ah*bl + bh*al)*B + al*bl
 * a*b = ah*bh*B^2 + ((ah+al)(bh+bl)-al*bl-ah*bh)*B + al*bl
 */
int karatsuba_mul(BIGNUM *_r, const BIGNUM *a, const BIGNUM *b) {
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

	uint32_t scratch_size = k_scratch_req(max(a->size, b->size));
	uint64_t *scratch = malloc(scratch_size * sizeof(uint64_t));

	k_mul_words(r.d, a->d, a->size, b->d, b->size, scratch);

	free(scratch);

	if(bnu_trim(&r) != 0 || bnu_free(_r) != 0) {
		return 1;
	}

	*_r = r;
	return 0;
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

	x_mul_words(r.d, a->d, a->size, b->d, b->size);

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

