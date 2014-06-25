#include <stdio.h>

#include "bignum.h"

int main() {
	BIGNUM a, b, c;
	bni_fstr(&a, "ec154596e28d60228c0b3");
	bni_fstr(&b, "baa5bffffff00efffff0f");
	bni_fstr(&c, "1f29285726fb9a9d05a97");
	uint32_t i;
	for(i = 0; i < a.size; i++) {
		printf("%llx\n", a.d[i]);
	}
	char out[100024];
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

	bnu_tstr(out, &a);
	printf("%s\n", out);
	bnu_tstr(out, &b);
	printf("%s\n", out);

	bno_mul(&r, &a, &b);
	bnu_tstr(out, &r);
	printf("%s\n", out);

	/*
	bnu_free(&b);
	bni_fstr(&b, "f");

	bno_exp(&r, &a, &b);*/

	bno_rmod(&r, &a, &b);

	bnu_tstr(out, &r);
	printf("%s\n", out);

	bno_mul_mod(&r, &a, &b, &c);

	bnu_tstr(out, &r);
	printf("%s\n", out);

	bnu_free(&a);
	bnu_free(&b);
	bnu_free(&r);
	bnu_free(&c);
}
