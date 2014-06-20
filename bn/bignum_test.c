#include <stdio.h>

#include "bignum.h"

int main() {
	BIGNUM a;
	bni_fstr(&a, "aaa5bffffff00ffffff0f");
	uint32_t i;
	for(i = 0; i < a.size; i++) {
		printf("%llx\n", a.d[i]);
	}
}
