#include <stdlib.h>

#include "bignum.h"
#include "bignum_util.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

/* returns 1 if there was a carry, 0 if not */
int add_words(uint64_t *r, uint64_t *a, const uint32_t alen, uint64_t *b, const uint32_t blen) {
	uint64_t t0, t1;
	uint32_t i;
	int carry = 0;
	const int bound = min(alen, blen);
	for(i = 0; i < bound; i++) {
		t0 = a[i] + carry;
		carry = (t0 < a[i]); /* C standard 3.3.8 */
		t1 = t0 + b[i];
		carry |= (t1 < t0);
		r[i] = t1;
	}

	while(i < alen) {
		t0 = a[i] + carry;
		carry = (t0 < a[i]);
		r[i] = t0;
		i++;
	}
	while(i < blen) {
		t0 = b[i] + carry;
		carry = (t0 < b[i]);
		r[i] = t0;
		i++;
	}

	return carry;
}

/* returns 1 if there was a carry, 0 if not */
int sub_words(uint64_t *r, uint64_t *a, const uint32_t alen, uint64_t *b, const uint32_t blen) {
	uint64_t t0, t1;
	uint32_t i;
	int carry = 0;
	const int bound = min(alen, blen);
	for(i = 0; i < bound; i++) {
		t0 = a[i] - carry;
		carry = (a[i] < t0);
		t1 = t0 - b[i];
		carry |= (t0 < t1);
		r[i] = t1;
	}

	while(i < alen) {
		t0 = a[i] - carry;
		carry = (a[i] < t0);
		r[i] = t0;
		i++;
	}

	return carry;
}

int bno_add(bignum *r, const bignum *a, const bignum *b) {
	if(r == NULL || a == NULL || b == NULL) {
		return -1;
	}

	/* TODO: bounds checking */
	if(bnu_resize(r, max(a->size, b->size) + 1) != 0) {
		return 1;
	}

	int carry = add_words(r->d, a->d, a->size, b->d, b->size);
	if(carry) r->d[max(a->size, b->size)] = 1;

	return bnu_trim(r);
}

int bno_add_mod(bignum *r, const bignum *a, const bignum *b, const bignum *n) {
	if(bno_add(r, a, b) != 0) {
		return 1;
	}

	return bno_rmod(r, r, n);
}

int bno_sub(bignum *r, const bignum *a, const bignum *b) {
	if(r == NULL || a == NULL || b == NULL) {
		return -1;
	}

	int cmp = bno_cmp(a, b);

	if(cmp == 0) {
		return bnu_resize(r, 0);
	}

	/* TODO: bounds checking */
	if(bnu_resize(r, max(a->size, b->size)) != 0) {
		return 1;
	}

	sub_words(r->d, a->d, a->size, b->d, b->size);

	return bnu_trim(r);
}
