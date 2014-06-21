#include <stdio.h>

#include "bignum.h"

int main() {
	BIGNUM a, b;
	bni_fstr(&a, "-0");
	bni_fstr(&b, "0");
	uint32_t i;
	for(i = 0; i < a.size; i++) {
		printf("%llx\n", a.d[i]);
	}

	printf("%d\n", bno_cmp(&a, &b));
}
