#include <stdio.h>

#include "bignum.h"

int main() {
	BIGNUM a, b;
	bni_fstr(&a, "caa5bffffff00efffff0f");
	bni_fstr(&b, "-baa5bffffff00efffff0f");
	uint32_t i;
	for(i = 0; i < a.size; i++) {
		printf("%llx\n", a.d[i]);
	}
	char out[64];
	bnu_tstr(out, &a);
	printf("%s\n", out);
	bnu_tstr(out, &b);
	printf("%s\n", out);

	printf("%d\n", bno_cmp(&a, &b));

	BIGNUM r = BN_ZERO;
	bno_add(&r, &a, &b);

	bnu_tstr(out, &r);

	printf("%s\n", out);

	bnu_tstr(out, &a);
	printf("%s\n", out);
	bno_lshift(&a, &a, 65);
	bnu_tstr(out, &a);
	printf("%s\n", out);
	bno_rshift(&a, &a, 63);
	bnu_tstr(out, &a);
	printf("%s\n", out);

	bnu_free(&a);
	bnu_free(&b);
	bnu_free(&r);
}
