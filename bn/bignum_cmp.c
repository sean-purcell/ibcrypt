#include <stdlib.h>

#include "bignum.h"
#include "bignum_util.h"

/* returns 1 if a > b, -1 if a < b, 0 if a == b
 * ignores sign */
int bno_ucmp(const BIGNUM* a, const BIGNUM* b) {
	if(a == NULL || b == NULL) {
		if(a == NULL) {
			return -1;
		}
		if(b == NULL) {
			return 1;
		}
		return 0;
	}

	if(a->size != b->size) {
		return a->size > b->size ? 1 : -1;
	}

	int result = 0;
	uint32_t i = a->size;
	while(i-- != 0) {
		if(a->d[i] != b->d[i] && result == 0) {
			result = a->d[i] > b->d[i] ? 1 : -1;
		}
	}
	return result;
}

/* returns 1 if a > b, -1 if a < b, 0 if a == b
 * note: -0 < 0 */
int bno_cmp(const BIGNUM* a, const BIGNUM* b) {
	if(a == NULL || b == NULL) {
		if(a == NULL) {
			return -1;
		}
		if(b == NULL) {
			return 1;
		}
		return 0;
	}

	if(a->neg != b->neg) {
		return a->neg ? -1 : 1;
	}

	int mul = 1;
	if(a->neg) {
		mul = -1;
	}

	return bno_ucmp(a, b) * mul;
}
