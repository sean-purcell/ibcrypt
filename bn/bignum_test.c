#include <stdio.h>

#include "bignum.h"

int main() {
	BIGNUM a, b;
	bni_fstr(&a, "caa5bffffff00efffff0f");
	bni_fstr(&b, "baa5bffffff00efffff0f");
	uint32_t i;
	for(i = 0; i < a.size; i++) {
		printf("%llx\n", a.d[i]);
	}

	printf("%d\n", bno_cmp(&a, &b));

	BIGNUM r;
	bno_add(&r, &a, &b);

}
