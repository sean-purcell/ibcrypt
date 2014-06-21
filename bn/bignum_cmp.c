#include <stdlib.h>

#include "bignum.h"
#include "bignum_util.h"

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

	int gt, lt; /* return value for unsigned gt or lt */

	if(a->neg) {
		gt = -1; lt = 1;
	} else {
		gt = 1; lt = -1;
	}

	if(a->size != b->size) {
		return a->size > b->size ? gt : lt;
	}

	int result = 0;
	uint32_t i = a->size;
	while(i-- != 0) {
		if(a->d[i] != b->d[i] && result == 0) {
			result = a->d[i] > b->d[i] ? gt : lt;
		}
	}
	return result;
}
