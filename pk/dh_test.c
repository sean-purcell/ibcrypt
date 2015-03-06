#include <stdio.h>
#include <stdlib.h>

#include <libibur/util.h>

#define IBCRYPT_BUILD
#include "dh.h"
#include "dh_util.h"
#undef IBCRYPT_BUILD

#define check() do { if(ret) fprintf(stderr, "%d :C", __LINE__); } while(0);

int main() {
	DH_CTX ctx;
	DH_PRI e1 = DH_VAL_INIT;
	DH_PRI e2 = DH_VAL_INIT;
	DH_PUB p1 = DH_VAL_INIT;
	DH_PUB p2 = DH_VAL_INIT;
	DH_PUB w1 = DH_VAL_INIT;
	DH_PUB w2 = DH_VAL_INIT;
	DH_VAL s1 = DH_VAL_INIT;
	DH_VAL s2 = DH_VAL_INIT;
	uint8_t *b1, *b2;

	int ret;

	ret = dh_init_ctx(&ctx, 14);
	check();

	printf("DH modulus:\n");
	bnu_print(&ctx.p);
	puts("\n");

	printf("DH bound:\n");
	bnu_print(&ctx.q);
	puts("\n");

	ret = dh_gen_exp(&ctx, &e1);
	check();
	ret = dh_gen_exp(&ctx, &e2);
	check();

	printf("DH exponents:\n");
	bnu_print(&e1.x);
	puts("\n");
	bnu_print(&e2.x);
	puts("\n");

	ret = dh_gen_pub(&ctx, &e1, &p1);
	check();
	ret = dh_gen_pub(&ctx, &e2, &p2);
	check();

	printf("DH public values:\n");
	b1 = malloc(dh_valwire_bufsize(&p1));
	ret = dh_val2wire(&p1, b1, dh_valwire_bufsize(&p1));
	check();
	b2 = malloc(dh_valwire_bufsize(&p2));
	ret = dh_val2wire(&p2, b2, dh_valwire_bufsize(&p2));
	check();

	printbuf(b1, dh_valwire_bufsize(&p1));
	puts("");
	printbuf(b2, dh_valwire_bufsize(&p2));
	puts("");

	ret = dh_wire2val(b1, dh_valwire_bufsize(&p1), &w1);
	check();
	ret = dh_wire2val(b2, dh_valwire_bufsize(&p2), &w2);
	check();

	free(b1);
	free(b2);

	ret = dh_compute_secret(&ctx, &e1, &w2, &s1);
	check();
	ret = dh_compute_secret(&ctx, &e2, &w1, &s2);
	check();

	printf("DH secret values:\n");
	b1 = malloc(dh_valwire_bufsize(&s1));
	ret = dh_val2wire(&s1, b1, dh_valwire_bufsize(&s1));
	check();
	b2 = malloc(dh_valwire_bufsize(&s2));
	ret = dh_val2wire(&s2, b2, dh_valwire_bufsize(&s2));
	check();

	printbuf(b1, dh_valwire_bufsize(&s1));
	puts("");
	printbuf(b2, dh_valwire_bufsize(&s2));
	puts("");
}

