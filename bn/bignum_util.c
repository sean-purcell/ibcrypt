#include <stdlib.h>
#include <stdint.h>

#include "bignum.h"
#include "bignum_util.h"

/* size is in 64 bit blocks */
int bnu_resize(BIGNUM* r, uint32_t size) {
	if(r->size == size) {
		return 0;
	}

	/* check for realloc fail */
	uint64_t* ptr = realloc(r->d, sizeof(uint64_t) * (uint64_t) size);
	if(ptr == NULL) {
		return 1;
	}
	r->d = ptr;

	/* zero allocated space */
	for(uint32_t i = r->size; i < size; i++) {
		r->d[i] = 0;
	}
	r->size = size;
	return 0;
}

int bnu_trim(BIGNUM* r) {
	if(r == NULL) {
		return -1;
	}

	if(r->size == 0) {
		return 0;
	}

	int64_t i = r->size; /* use signed so that we can go lower than 0 */
	do {
		i--;
	} while(r->d[i] == 0 && i >= 0);

	return bnu_resize(r, (uint32_t) (i + 1));
}
