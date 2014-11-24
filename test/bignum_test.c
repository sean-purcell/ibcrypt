#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <bignum.h>

static void bn_err(const char* err) {
	fprintf(stderr, "bignum lib error: %s\n", err);
	exit(1);
}

static void bn_mul_test() {
	const uint32_t sizes[] = { 32, 64 }; //, 256, 2048, 4096 };
	const uint32_t tests[] = {100,100 }; //, 100,   50,   50 };

	BIGNUM a = BN_ZERO;
	BIGNUM b = BN_ZERO;
	BIGNUM r = BN_ZERO;
	int i;
	for(i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
		int j;
		char* astr = malloc((sizes[i] + 63) / 64 * 16 + 1);
		char* bstr = malloc((sizes[i] + 63) / 64 * 16 + 1);
		char* res = malloc((sizes[i] + 63) / 64 * 32 + 1);
		for(j = 0; j < tests[i]; j++) {
			if(bni_rand_bits(&a, sizes[i]) != 0 ||
			   bni_rand_bits(&b, sizes[i]) != 0) {
				bn_err("rand");
			}

			if(bno_mul(&r, &a, &b) != 0) {
				bn_err("mul");
			}

			bnu_tstr(astr, &a);
			bnu_tstr(bstr, &b);
			bnu_tstr(res, &r);
			printf("%s*\n%s=\n%s\n\n", astr, bstr, res);
		}

		free(astr);
		free(bstr);
		free(res);
	}

	bnu_free(&a);
	bnu_free(&b);
	bnu_free(&r);
}

void bignum_tests() {
	bn_mul_test();
}

