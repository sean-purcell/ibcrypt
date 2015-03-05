#include <stdio.h>
#include <stdlib.h>

#define IBCRYPT_BUILD
#include "dh.h"
#undef IBCRYPT_BUILD

#define check() do { if(ret) fprintf(stderr, "%d :C", __LINE__); } while(0);

int main() {
	DH_CTX ctx;
	DH_PRI e1, e2;
	DH_PUB p1, p2;
	DH_VAL s1, s2;

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
	bnu_print(&p1.x);
	puts("\n");
	bnu_print(&p2.x);
	puts("\n");

	ret = dh_compute_secret(&ctx, &e1, &p2, &s1);
	check();
	ret = dh_compute_secret(&ctx, &e2, &p1, &s2);
	check();

	printf("DH secret values:\n");
	bnu_print(&s1.x);
	puts("\n");
	bnu_print(&s2.x);
	puts("\n");
}

