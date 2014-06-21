#include <stdlib.h>

#include "bignum.h"
#include "bignum_util.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
int bno_uadd(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	if(r == NULL || a == NULL || b == NULL) {
		return -1;
	}

	/* TODO: bounds checking */
	bnu_resize(r, max(a->size, b->size) + 1);

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

	r->neg = a->neg;

	bnu_trim(r);

	return 0;
}

int bno_usub(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	if(r == NULL || a == NULL || b == NULL) {
		return -1;
	}

	int cmp = bno_ucmp(a, b);

	if(cmp == 0) {
		bnu_resize(r, 0);
		return 0;
	}

	int swapped = 0;
	if(cmp == -1) {
		const BIGNUM* tmp = a;
		a = b;
		b = tmp;
		swapped = 1;
	}

	/* TODO: bounds checking */
	bnu_resize(r, max(a->size, b->size));

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

	r->neg = swapped ? -b->neg : a->neg;

	bnu_trim(r);

	return 0;
}

int bno_add(BIGNUM* r, const BIGNUM* a, const BIGNUM* b) {
	if(a->neg == b->neg) {
		return bno_uadd(r, a, b);
	} else {
		return bno_usub(r, a, b);
	}
}
