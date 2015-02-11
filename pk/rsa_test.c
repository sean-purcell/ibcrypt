#include <stdint.h>

#include "../libibur/util.h"
#include "../bn/bignum.h"
#define IBCRYPT_BUILD
#include "rsa.h"
#undef IBCRYPT_BUILD

void i2os_os2i_test() {
	uint8_t i[8] = { 0x00, 0x53, 0xef, 0x42, 0xb3, 0x9e, 0x1c, 0xf4 };
	uint8_t o[9];
	bignum m = BN_ZERO;
	os2ip(&m, i, 8);
	i2osp(o, 7, &m);

	printbuf(i, 8);
	bnu_print(&m);puts("");
	printbuf(o, 9);

	bnu_free(&m);
}

void rsa_test() {
	RSA_KEY key;
	RSA_PUBLIC_KEY pkey;
	rsa_gen_key(&key, 2048, 65537);
	rsa_pub_key(&key, &pkey);

	printf("n:\n");bnu_print(&key.n);puts("");
	printf("p:\n");bnu_print(&key.p);puts("");
	printf("q:\n");bnu_print(&key.q);puts("");
	printf("d:\n");bnu_print(&key.d);puts("");
	printf("e:\n%llu\n", key.e);

	/* test encryption and decryption of message */
	char *message = "this is my secret.  there are many like it, but this one is mine.";
	uint8_t *ctext = malloc(key.n.size * 8);
	uint8_t *sig = malloc(key.n.size * 8);
	char *mtext = malloc(strlen(message) + 1);

	int ret = rsa_oaep_encrypt(&pkey, (uint8_t*) message, strlen(message) + 1, ctext, key.n.size * 8);
	printf("%d\n", ret);
	printbuf(ctext, key.n.size * 8);

	ret = rsa_pss_sign(&key, ctext, key.n.size * 8, sig, key.n.size * 8);
	printf("%d\n", ret);
	printbuf(sig, key.n.size * 8);

	ret = rsa_oaep_decrypt(&key, ctext, key.n.size * 8, (uint8_t*)mtext, strlen(message) + 1);
	printf("%d\n", ret);
	printf("%s\n", mtext);

	int valid = 0;
	ret = rsa_pss_verify(&pkey, sig, key.n.size * 8, ctext, key.n.size * 8, &valid);
	printf("%d\n", ret);
	printf("valid:%d\n", valid);

	ctext[128] ^= 1;
	ret = rsa_oaep_decrypt(&key, ctext, key.n.size * 8, (uint8_t*)mtext, strlen(message) + 1);
	printf("%d\n", ret);

	sig[4] ^= 0x8;
	valid = 0;
	ret = rsa_pss_verify(&pkey, sig, key.n.size * 8, ctext, key.n.size * 8, &valid);
	printf("%d\n", ret);
	printf("valid:%d\n", valid);
}

int main() {
	//i2os_os2i_test();
	rsa_test();
}

