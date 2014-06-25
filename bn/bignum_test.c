#include <stdio.h>

#include "bignum.h"

int main() {
	BIGNUM a, b;
	bni_fstr(&a, "ec154596e28d60228c0b3bedc1280600977e65276bb00aa55012ff9b745982b9778ba97bedaef0066608aeb7224ccac1efcaa78351b9a91cd8c0fe136b748184a6bc809553762c9ba8b5dd5ca39a70ec3f2ff7609ee2e6781196d148042c00fd1fa0933dfb6023cfb2890b5bfaddd4edf9a5bbd8111c1bbeb5875417f61b35b97d36b718d714d71136c5008f0a16ebf729fb240d8f2128f65b47c657e6a469d4609fc4a1f1f7d7ce2a99bf37c15787c406534b2ffdcdbead3ee7717f8f99d9bfca8c99ec26c4ed1ea2fc6601fba6abf9401e5abbb80889cd5899344ac795e08ea8e97d836e8fb1e5316ee5bc6872ec4f33c5f3384191f29285726fb9a9d05a97");
	bni_fstr(&b, "baa5bffffff00efffff0f");
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

	bnu_free(&a);
	bnu_free(&b);
	bnu_free(&r);
}
