#include <stdlib.h>

#include "bignum.h"
#include "bignum_util.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

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

	BIGNUM _a = *a;
	BIGNUM _b = *b;

	uint64_t* ad = _a.d;
	uint64_t* bd = _b.d;

	int result = 0;
	uint32_t i = max(_a.size, _b.size);
	while(i > _b.size) {
		i--;
		if(ad[i] != 0) result = 1;
	}
	while(i > _a.size) {
		i--;
		if(bd[i] != 0) result = -1;
	}
	while(i-- != 0) {
		if(ad[i] != bd[i] && result == 0) {
			result = ad[i] > bd[i] ? 1 : -1;
		}
	}
	return result;
}
