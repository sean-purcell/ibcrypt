#include <stdint.h>

#include "zfree.h"

void *memsets(void *p, int v, size_t n) {
	volatile uint64_t *v64p = p;
	volatile uint8_t *v8p = p;
	const uint64_t val = ((uint64_t)v << 56) | ((uint64_t)v << 48) |
	                     ((uint64_t)v << 40) | ((uint64_t)v << 32) |
	                     ((uint64_t)v << 24) | ((uint64_t)v << 16) |
			     ((uint64_t)v <<  8) | (uint64_t)v;

	size_t i;
	const size_t max = n / 8;
	for(i = 0; i < max; i++) {
		v64p[i] = val;
	}

	size_t j;
	for(j = i * 8; j < n; j++) {
		v8p[i] = v;
	}

	return p;
}

void zfree(void *p, size_t n) {
	memsets(p, 0, n);
	free(p);
}

