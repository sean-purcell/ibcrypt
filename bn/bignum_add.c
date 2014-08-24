#include <stdlib.h>

#include "bignum.h"
#include "bignum_util.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

/* returns 1 if there was a carry, 0 if not */
int add_words(uint64_t* r, uint64_t* a, uint32_t alen, uint64_t* b, uint32_t blen) {
	uint64_t t0, t1;
	uint32_t i;
	int carry = 0;
	for(i = 0; i < min(alen, blen); i++) {
		t0 = a[i] + carry;
		carry = (t0 < a[i]); /* C standard 3.3.8 */
		t1 = t0 + b[i];
		carry = (t1 < t0);
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
int sub_words(uint64_t* r, uint64_t* a, uint32_t alen, uint64_t* b, uint32_t blen);

void bno_add_no_resize(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	int carry = add_words(r->d, a->d, a->size, b->d, b->size);
	if(carry) r->d[max(a->size, b->size)] = 1;
}

int bno_add_mod_no_resize(BIGNUM* r, const BIGNUM* a, const BIGNUM* b, const BIGNUM* n) {
	bno_add_no_resize(r, a, b);

	return bno_rmod_no_resize(r, n);
}

int bno_add(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	if(r == NULL || a == NULL || b == NULL) {
		return -1;
	}

	/* TODO: bounds checking */
	if(bnu_resize(r, max(a->size, b->size) + 1) != 0) {
		return 1;
	}

	bno_add_no_resize(r, a, b);

	if(bnu_trim(r) != 0) {
		return 1;
	}

	return 0;
}

int bno_add_mod(BIGNUM* r, const BIGNUM* a, const BIGNUM* b, const BIGNUM* n) {
	if(bno_add(r, a, b) != 0) {
		return 1;
	}

	return bno_rmod(r, r, n);
}

void bno_sub_no_resize(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	uint64_t t0, t1;
	uint32_t i;
	int carry = 0;
	for(i = 0; i < b->size; i++) {
		t0 = a->d[i] - carry;
		carry = (a->d[i] < t0);
		t1 = t0 - b->d[i];
		carry = (t0 < t1);
		r->d[i] = t1;
	}

	while(i < a->size) {
		t0 = a->d[i] - carry;
		carry = (a->d[i] < t0);
		r->d[i] = t0;
		i++;
	}
}

int bno_sub(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
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

	bno_sub_no_resize(r, a, b);

	return bnu_trim(r);
}
