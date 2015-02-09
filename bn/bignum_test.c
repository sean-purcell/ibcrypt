#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "bignum.h"
#include "../hash/sha256.h"

#include <libibur/util.h>

int bno_barrett_rmod(bignum *_r, const bignum *a, const bignum *n);
int rabin_miller(int *r, const bignum *n, const uint32_t certainty);
int karatsuba_mul(bignum *_r, const bignum *_a, const bignum *_b);
int cross_mul(bignum *_r, const bignum *_a, const bignum *_b);
int exp_mod_odd(bignum *_r, const bignum *m, const bignum *e, const bignum *n);
int fermat_test(int *r, const bignum *n);

void speed_test() {
	bignum m, e, n, r = BN_ZERO;
	char out[2048];
	bni_fstr(&m, "ced9c95986f5bf1805110bb5fb436fb5bd300ede4e5ad19d53c30f473b323f1f12b55ded63cdc6840612196870bdffffeee41157c1eed71dd3e4c60239f2a4401c87e33a328bf09b685f81fb50c7b5c81995c6af280ceceb8422e92bae75d19a5dff48e5c836d14045ea568074d49ca9647d665b37dc15b29604ae85ffa847d4d6315efb3adf6d3e3700f14d08f68ff448d78f650a95c123daa4f308f79fe23333c818fa85d457b32a75b51f9a1f69a386da6a35cbf75ad893a3bfa59633e48cf985b525ef63d7698a4faa75cf07c9303491ab61fc36549fc2c7eae38e2764aa9a0034a9f2f0c19ffe2589d26070ffa923302dedfe240c8e082403d3bad8fead");
	bni_fstr(&e, "a7c44d53a6175eab18c61802aad4dc00c498f0f184359d58e3616b9463b99b67cb93f525101c9db09f9e6e06d701fc1179f9343a3b2a5dc680d83476443c07041f9779d3801598f3df6c8a2cdd441a27c557f685ef8dd47615443a8831a83b7b00e561eef855820d3368aaacf1effc261803525de357f86cbaa18a706b67c134077b6476afd297340916d28b20c6de071f40bf8129aaf7c6cb3db05e228e0afb2c95f6c117a505f038cebc955d438dad11dee77ab3ea19dcf8a372e6dda7bd77458fc57b141ce6eaaf56e882bc1a87be677d02e087f3e60832f9b2c660cb82f3badccd36f1c1616b468928f45e25d6edb2c4fbcf0c0bf75ba9ea75930599f451");
	bni_fstr(&n, "b05bde88ecc32ffa109dd630ad46dc12d889ecdc536a82e9784b570fd7932a8b9081b1a15922d09921a29fd7c95ab1bf851476c3b0a35497c525b4e984af3e814e05325d1be5ddfab399c0b0fc5c48cfb3d8d4dca8b7fdbd3bc9c12adc67f89f361e2afe63867eb763114d988579e0cb02af6ca6772e3ab6679d83aee70b0007df5818a825c346a9167f3629ad1a408ae4520f346ef594c3f1b3318f746025f200ae53ec152adfbdedee89bbf5e877a4f174b95a6ce5438c6ed26cdf098a448a9cfaafa13b18450ddf44abda147efa0d44ff934bb6565076e4b31fc401171e01f2fab7b9a65fa1941edbacc5c6b831329bbac9b5dc79053029454971891938f5");
	bnu_tstr(out, &m);
	printf("m    :%s\n", out);

	bnu_tstr(out, &e);
	printf("e    :%s\n", out);

	bnu_tstr(out, &n);
	printf("n    :%s\n", out);

	bni_rand_range(&r, &BN_ZERO, &m);
	bnu_tstr(out, &r);
	printf("rand<m:%s\n", out);

	bno_mul(&r, &m, &n);
	bnu_tstr(out, &r);
	printf("m*n  :%s\n", out);

	karatsuba_mul(&r, &m, &n);
	bnu_tstr(out, &r);
	printf("m*n  :%s\n", out);

	bno_neg_mod(&r, &m, &n);
	bnu_tstr(out, &r);
	printf("-m%%n :%s\n", out);

	bno_inv_mod(&r, &m, &n);
	bnu_tstr(out, &r);
	printf("m-1%%n:%s\n", out);

	bno_exp_mod(&r, &e, &n, &m);
	bnu_tstr(out, &r);
	printf("e^n%%m:%s\n", out);

	exp_mod_odd(&r, &e, &n, &m);
	bnu_tstr(out, &r);
	printf("e^n%%m:%s\n", out);

	int prime = 5;
	printf("%d\n", rabin_miller(&prime, &m, 128));
	printf("mprime:%d\n", prime);

	bnu_free(&m);
	bnu_free(&e);
	bnu_free(&n);
	bnu_free(&r);
}

int prime_test(int *r, const bignum *n, const uint32_t certainty);
void prime_test_test() {
	bignum m;
	bni_fstr(&m, "ced9c95986f5bf1805110bb5fb436fb5bd300ede4e5ad19d53c30f473b323f1f12b55ded63cdc6840612196870bdffffeee41157c1eed71dd3e4c60239f2a4401c87e33a328bf09b685f81fb50c7b5c81995c6af280ceceb8422e92bae75d19a5dff48e5c836d14045ea568074d49ca9647d665b37dc15b29604ae85ffa847d4d6315efb3adf6d3e3700f14d08f68ff448d78f650a95c123daa4f308f79fe23333c818fa85d457b32a75b51f9a1f69a386da6a35cbf75ad893a3bfa59633e48cf985b525ef63d7698a4faa75cf07c9303491ab61fc36549fc2c7eae38e2764aa9a0034a9f2f0c19ffe2589d26070ffa923302dedfe240c8e082403d3bad8fead");

	int prime;
	prime_test(&prime, &m, 128);
	printf("mprime:%d\n", prime);
}

void prime_gen_test() {
	bignum p;
	bni_rand_prime(&p, 1024, 128);
	char *out = malloc(513);
	bnu_tstr(out, &p);
	printf("p:%s\n", out);
	bnu_free(&p);
	free(out);
}

void karatsuba_test() {
	char *out = malloc(2049);
	puts("karatsuba test");
	bignum a = BN_ZERO;
	bignum b = BN_ZERO;

	bignum max = BN_ZERO;
	bignum min = BN_ZERO;

	bignum xr = BN_ZERO,
	       kr = BN_ZERO;

	bni_2power(&max, 2048);

	bni_rand_range(&a, &min, &max);
	bni_rand_range(&b, &min, &max);

	bnu_tstr(out, &a);
	printf("a    :%s\n", out);
	bnu_tstr(out, &b);
	printf("b    :%s\n", out);

	bno_mul(&xr, &a, &b);
	karatsuba_mul(&kr, &a, &b);

	bnu_tstr(out, &xr);
	printf("a*b r:%s\n", out);

	bnu_tstr(out, &kr);
	printf("a*b k:%s\n", out);

	int cmp = bno_cmp(&xr, &kr);
	printf("cmp  :%d\n", cmp);

	free(out);
	bnu_free(&a);
	bnu_free(&b);
	bnu_free(&max);
	bnu_free(&min);
	bnu_free(&xr);
	bnu_free(&kr);
}

void karatsuba_speed_test() {
	const size_t N = 16384;
	const uint32_t B = 2048;
	bignum *a = malloc(N * sizeof(bignum));
	bignum *b = malloc(N * sizeof(bignum));
	bignum *x = malloc(N * sizeof(bignum));
	bignum *k = malloc(N * sizeof(bignum));

	bignum max = BN_ZERO;
	bignum min = BN_ZERO;

	clock_t start, end;

	bni_2power(&max, B);

	for(int i = 0; i < N; i++) {
		a[i] = BN_ZERO;
		b[i] = BN_ZERO;

		bni_rand_range(&a[i], &min, &max);
		bni_rand_range(&b[i], &min, &max);
	}

	start = clock();
	for(int i = 0; i < N; i++) {
		cross_mul(&x[i], &a[i], &b[i]);
	}
	end = clock();
	printf("%zu %u-bit xmuls done in %fs\n", N, B, (float)(end-start)/CLOCKS_PER_SEC);

	start = clock();
	for(int i = 0; i < N; i++) {
		karatsuba_mul(&k[i], &a[i], &b[i]);
	}
	end = clock();
	printf("%zu %u-bit kmuls done in %fs\n", N, B, (float)(end-start)/CLOCKS_PER_SEC);

	SHA256_CTX xsha, ksha;
	sha256_init(&xsha);
	sha256_init(&ksha);

	for(int i = 0; i < 1024; i++) {
		sha256_update(&xsha, (uint8_t*) x[i].d, x[i].size * sizeof(uint64_t));
		sha256_update(&ksha, (uint8_t*) k[i].d, k[i].size * sizeof(uint64_t));
	}

	uint8_t xdig[32];
	uint8_t kdig[32];

	sha256_final(&xsha, xdig);
	sha256_final(&ksha, kdig);

	printf("xdig:");
	printbuf(&xdig, 32);
	printf("kdig:");
	printbuf(&kdig, 32);

	free(a);
	free(b);
	free(x);
	free(k);
}

void rand_exp_test() {
	char out[1025];
	puts("rand exp test");
	bignum a = BN_ZERO;
	bignum b = BN_ZERO;
	bignum c = BN_ZERO;

	bignum max = BN_ZERO;
	bignum min = BN_ZERO;
	
	bignum r = BN_ZERO;

	bni_2power(&max, 2048);

	bni_rand_range(&a, &min, &max);
	bni_rand_range(&b, &min, &max);
	bni_rand_range(&c, &min, &max);

	bnu_tstr(out, &a);
	printf("a    :%s\n", out);
	bnu_tstr(out, &b);
	printf("b    :%s\n", out);
	bnu_tstr(out, &c);
	printf("c    :%s\n", out);

	bno_exp_mod(&r, &a, &b, &c);

	bnu_tstr(out, &r);
	printf("a^b%%c:%s\n", out);

	char astr[1025];
	char bstr[1025];
	char cstr[1025];
	bnu_tstr(astr, &a);
	bnu_tstr(bstr, &b);
	bnu_tstr(cstr, &c);

	char command[4096];
	sprintf(command, "python -c 'print(\"rand exp test passes:\");print(pow(0x%s,0x%s,0x%s)==0x%s)'", astr, bstr, cstr, out);
	printf("command: %s\n", command);
	system(command);

	bnu_free(&a);
	bnu_free(&b);
	bnu_free(&c);
	bnu_free(&max);
	bnu_free(&min);
	bnu_free(&r);
}

void assorted() {
	bignum a, b, c;
	bni_fstr(&a, "ec154596e28d60228c0b3ec154596e28d60228c0b3ec154596e28d60228c0b3ec154596e28d60228c0b3");
	bni_fstr(&b, "baa5bffffff00efffff0f1f29285726fb9a9d05a97baa5bffffff00efffff0f1f29285726fb9a9d05a97");
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

	bignum r = BN_ZERO;
	bno_add(&r, &a, &b);

	//bnu_tstr(out, &r);

	//printf("%s\n", out);

	bno_mul(&r, &a, &b);
	bnu_tstr(out, &r);
	printf("a*b  :%s\n", out);

	printf("a*b  :%s\n", out);

	bno_mul_mod(&r, &a, &b, &c);
	bnu_tstr(out, &r);
	printf("a*b%%c:%s\n", out);

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

//	exp_mod_odd(&r, &a, &b, &c);
//	bnu_tstr(out, &r);
//	printf("a^b%%c:%s\n", out);

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

	bno_mul(&r, &a, &a);
	bnu_tstr(out, &r);
	printf("a*a  :%s\n", out);
	bno_rmod(&r, &r, &c);
	bnu_tstr(out, &r);
	printf("a*a%%c:%s\n", out);

	bno_rmod(&r, &a, &c);
	bnu_tstr(out, &r);
	printf("a%%c  :%s\n", out);

	bignum q;
	bni_fstr(&q, "a0affdb1bfa248f18fb1cb50c4e22179d39c823bb4f8277024327f64aa6f2a2dd7cb07f4ab56ed027843c33dca6e6c60be8ceaec2dfef201fbf8e98036161b64fdd57456c09732c0b2998074890ae13496a332d065768706f0ab9c20f5f05b4411bae43a20e7ae445bb3cc131064a67a5fb713ca0dd5335f52d22c26482c53521f1029f77191f668d60215ca0a8f616c5c5e14f93df33df2dd2fe64b83c8cd2d4747b15c2dbfe9c2f583bee38d0f10f6a35958284091afd45abcb83c024f28a4a4a21504c0ce9104fe1c5b09e781d2749fe39eb7f5f916b48fe4669d6f70960f85682340e96b808b097fcca0955c93b4d2ce3b8b548f0c423a6a7c37f6d0618f");

	bnu_tstr(out, &q);
	printf("q    :%s\n", out);

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

	bno_mul(&r, &a, &c);
	bno_barrett_rmod(&r, &r, &b);
	bnu_tstr(out, &r);
	printf("a*c%%b:%s\n", out);

	bno_div(&r, &a, &c);
	bnu_tstr(out, &r);
	printf("a/c  :%s\n", out);

	bno_div(&r, &q, &b);
	bnu_tstr(out, &r);
	printf("q/b  :%s\n", out);

	bnu_tstr(out, &a);
	printf("a    :%s\n", out);
	bnu_tstr(out, &b);
	printf("b    :%s\n", out);
	bnu_tstr(out, &c);
	printf("c    :%s\n", out);

	bignum five = BN_ZERO, four = BN_ZERO;
	bni_fstr(&five, "5");
	bni_fstr(&four, "4");

	bno_inv_mod(&r, &five, &four);
	bnu_tstr(out, &r);
	printf("5iv%%4:%s\n", out);
	bno_inv_mod(&r, &four, &five);
	bnu_tstr(out, &r);
	printf("4iv%%5:%s\n", out);

	bignum x = BN_ZERO, y = BN_ZERO;
	bni_fstr(&x, "17");
	bni_fstr(&y, "20");
	bno_inv_mod(&r, &y, &x);
	bnu_tstr(out, &r);
	printf("xiv%%n:%s\n", out);

	bno_inv_mod(&r, &five, &x);
	bnu_tstr(out, &r);
	printf("5iv%%x:%s\n", out);

	exp_mod_odd(&r, &five, &y, &x);
	bnu_tstr(out, &r);
	printf("5^y%%x:%s\n", out);

	bni_rand_range(&r, &x, &y);
	bnu_tstr(out, &r);
	printf("randxy:%s\n", out);

	bni_fstr(&x, "22");
	bni_fstr(&y, "26");

	int prime = 0;
	fermat_test(&prime, &x);
	printf("%d\n", prime);

	bnu_free(&a);
	bnu_free(&b);
	bnu_free(&r);
	bnu_free(&c);
	bnu_free(&q);
	bnu_free(&five);
	bnu_free(&four);
	bnu_free(&y);
	bnu_free(&x);
}


int main() {
	//karatsuba_test();
	//karatsuba_speed_test();
	//speed_test();
	//rand_exp_test();
	//prime_test_test();
	prime_gen_test();
	//assorted();
}
