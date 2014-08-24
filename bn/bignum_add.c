#include <stdlib.h>

#include "bignum.h"
#include "bignum_util.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

void bno_add_no_resize(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	uint64_t t0, t1;
	uint32_t i;
	int carry = 0;
	for(i = 0; i < min(a->size, b->size); i++) {
		t0 = a->d[i] + carry;
		carry = (t0 < a->d[i]); /* C standard 3.3.8 */
		t1 = t0 + b->d[i];
		carry = (t1 < t0);
		r->d[i] = t1;
	}

	while(i < a->size) {
		t0 = a->d[i] + carry;
		carry = (t0 < a->d[i]);
		r->d[i] = t0;
		i++;
	}
	while(i < b->size) {
		t0 = b->d[i] + carry;
		carry = (t0 < b->d[i]);
		r->d[i] = t0;
		i++;
	}
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
