#include "zfree.h"

void *memsets(void *p, int v, size_t n) {
	volatile unsigned char *vp = p;

	while(n--) {
		*vp++ = v;
	}

	return p;
}

void zfree(void *p, size_t n) {
	memsets(p, 0, n);
	free(p);
}

