#include <stdlib.h>

#include "bignum.h"
#include "bignum_util.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

int cmp_words(const uint64_t* a, const uint32_t alen, const uint64_t* b, const uint32_t blen) {
	int result = 0;
	uint32_t i = max(alen, blen);
	while(i > blen) {
		i--;
		if(a[i] != 0) result = 1;
	}
	while(i > alen) {
		i--;
		if(b[i] != 0) result = -1;
	}
	while(i-- != 0) {
		if(a[i] != b[i] && result == 0) {
			result = a[i] > b[i] ? 1 : -1;
		}
	}

	return result;
}

/* returns 1 if a > b, -1 if a < b, 0 if a == b
 * ignores sign */
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

	return cmp_words(a->d, a->size, b->d, b->size);
}
