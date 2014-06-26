#include <stdio.h>

#include "bignum.h"

int main() {
	BIGNUM a, b, c;
	bni_fstr(&a, "ec154596e28d60228c0b3");
	bni_fstr(&b, "baa5bffffff00efffff0f");
//	bni_fstr(&b, "ff");
	bni_fstr(&c, "1f29285726fb9a9d05a97");
	uint32_t i;
	for(i = 0; i < a.size; i++) {
	//	printf("%llx\n", a.d[i]);
	}
	char out[100024];
	//bnu_tstr(out, &a);
	//printf("%s\n", out);
	//bnu_tstr(out, &b);
	//printf("%s\n", out);

	//printf("%d\n", bno_cmp(&a, &b));

	BIGNUM r = BN_ZERO;
	bno_add(&r, &a, &b);

	//bnu_tstr(out, &r);

	//printf("%s\n", out);

	//bnu_tstr(out, &a);
	//printf("%s\n", out);
	bno_lshift(&a, &a, 65);
	//bnu_tstr(out, &a);
	//printf("%s\n", out);
	bno_rshift(&a, &a, 63);
	//bnu_tstr(out, &a);
	//printf("%s\n", out);

	bnu_tstr(out, &a);
	printf("a    :%s\n", out);
	bnu_tstr(out, &b);
	printf("b    :%s\n", out);
	bnu_tstr(out, &c);
	printf("c    :%s\n", out);
	//bno_mul(&r, &a, &b);
	//bnu_tstr(out, &r);
	//printf("%s\n", out);

	bno_exp_mod(&r, &a, &b, &c);
	bnu_tstr(out, &r);
	printf("a^b%%c:%s\n", out);

	bno_mul_mod(&r, &a, &b, &c);
	bnu_tstr(out, &r);
	//printf("%s\n", out);

	bno_mul(&r, &a, &b);
	bno_rmod(&r, &r, &c);
	bnu_tstr(out, &r);
	//printf("%s\n", out);
	/*
	bnu_free(&b);
	bni_fstr(&b, "ef");
	bnu_tstr(out, &b);
	printf("%s\n", out);
	bno_exp(&r, &a, &b);
	bnu_tstr(out, &r);
	printf("%s\n", out);*/
	bno_rmod(&r, &r, &c);
	
	bnu_tstr(out, &r);
//	printf("%s\n", out);

	bno_mul_mod(&r, &a, &a, &c);
	bnu_tstr(out, &r);
	printf("a^2%%c:%s\n", out);

	BIGNUM two = BN_ZERO;
	bni_fstr(&two, "700000000000001");
	bno_exp_mod(&r, &a, &two, &c);
	bnu_tstr(out, &r);
	printf("a^70000000000000000%%c:%s\n", out);

	bno_mul(&r, &a, &a);
	bnu_tstr(out, &r);
	printf("a*a  :%s\n", out);
	bno_rmod(&r, &r, &c);
	bnu_tstr(out, &r);
	printf("a*a%%c:%s\n", out);

	bno_rmod(&r, &a, &c);
	bnu_tstr(out, &r);
	printf("a%%c  :%s\n", out);

	BIGNUM q;
	bni_fstr(&q, "a0affdb1bfa248f18fb1cb50c4e22179d39c823bb4f8277024327f64aa6f2a2dd7cb07f4ab56ed027843c33dca6e6c60be8ceaec2dfef201fbf8e98036161b64fdd57456c09732c0b2998074890ae13496a332d065768706f0ab9c20f5f05b4411bae43a20e7ae445bb3cc131064a67a5fb713ca0dd5335f52d22c26482c53521f1029f77191f668d60215ca0a8f616c5c5e14f93df33df2dd2fe64b83c8cd2d4747b15c2dbfe9c2f583bee38d0f10f6a35958284091afd45abcb83c024f28a4a4a21504c0ce9104fe1c5b09e781d2749fe39eb7f5f916b48fe4669d6f70960f85682340e96b808b097fcca0955c93b4d2ce3b8b548f0c423a6a7c37f6d0618f");

	bno_rmod(&r, &q, &a);
	bnu_tstr(out, &r);
	printf("q%%a  :%s\n", out);

	bno_mul(&r, &a, &c);
	bnu_tstr(out, &r);
	printf("a*c  :%s\n", out);

	bno_rmod(&r, &r, &a);
	bnu_tstr(out, &r);
	printf("a*c%%a:%s\n", out);

	bno_mul_mod(&r, &a, &c, &b);
	bnu_tstr(out, &r);
	printf("a*c%%b:%s\n", out);

	bnu_tstr(out, &a);
	printf("a    :%s\n", out);
	bnu_tstr(out, &b);
	printf("b    :%s\n", out);
	bnu_tstr(out, &c);
	printf("c    :%s\n", out);

	bnu_free(&a);
	bnu_free(&b);
	bnu_free(&r);
	bnu_free(&c);
}
