#include "zfree.h"

void *memset_s(void *p, int v, size_t n) {
	volatile unsigned char *vp = p;

	while(n--) {
		*vp++ = v;
	}

	return p;
}

void zfree(void *p, size_t n) {
	memset_s(p, 0, n);
	free(p);
}

