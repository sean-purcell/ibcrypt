#include <stdlib.h>

#include "bignum.h"
#include "bignum_util.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

void bno_uadd_no_resize(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
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

void bno_uadd_mod_no_resize(BIGNUM* r, const BIGNUM* a, const BIGNUM* b, const BIGNUM* n) {
	bno_uadd_no_resize(r, a, b);

	return bno_rmod_no_resize(r, n);
}

int bno_uadd(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	if(r == NULL || a == NULL || b == NULL) {
		return -1;
	}

	/* TODO: bounds checking */
	if(bnu_resize(r, max(a->size, b->size) + 1) != 0) {
		return 1;
	}

	bno_uadd_no_resize(r, a, b);

	r->neg = a->neg;

	if(bnu_trim(r) != 0) {
		return 1;
	}

	return 0;
}

int bno_uadd_mod(BIGNUM* r, const BIGNUM* a, const BIGNUM* b, const BIGNUM* n) {
	if(bno_uadd(r, a, b) != 0) {
		return 1;
	}

	return bno_rmod(r, r, n);
}

int bno_usub_no_resize(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {	
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

int bno_usub(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	if(r == NULL || a == NULL || b == NULL) {
		return -1;
	}

	int cmp = bno_ucmp(a, b);

	if(cmp == 0) {
		return bnu_resize(r, 0);
	}

	int swapped = 0;
	if(cmp == -1) {
		const BIGNUM* tmp = a;
		a = b;
		b = tmp;
		swapped = 1;
	}

	/* TODO: bounds checking */
	if(bnu_resize(r, max(a->size, b->size)) != 0) {
		return 1;
	}

	bno_usub_no_resize(r, a, b);

	r->neg = swapped ? -b->neg : a->neg;

	if(bnu_trim(r) != 0) {
		return 1;
	}

	return 0;
}

int bno_add(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	if(a->neg == b->neg) {
		return bno_uadd(r, a, b);
	} else {
		return bno_usub(r, a, b);
	}
}

#undef min
#undef max
