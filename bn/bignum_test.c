#include "bn/bignum.h"

int main() {
	BIGNUM a;
	bni_fstr(&a, "ffffffffffffffff");
	uint32_t i;
	for(i = 0; i < a.size; i++) {
		printf("%llu\n", a.d[i]);
	}
}
