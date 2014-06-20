#include <stdlib.h>
#include <stdint.h>

#include "bignum.h"
#include "bignum_util.h"

/* size is in 64 bit blocks */
int bnu_resize(BIGNUM* r, uint32_t size) {
	/* check for realloc fail */
	uint64_t* ptr = realloc(r->d, sizeof(uint64_t) * (uint64_t) size);
	if(ptr == 0) {
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
