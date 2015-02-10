#include <stdint.h>

#include "../libibur/util.h"
#include "../bn/bignum.h"
#define IBCRYPT_BUILD
#include "rsa.h"
#undef IBCRYPT_BUILD

void i2os_os2i_test() {
	uint8_t i[8] = { 0x10, 0x53, 0xef, 0x42, 0xb3, 0x9e, 0x1c, 0xf4 };
	uint8_t o[8];
	bignum m;
	os2ip(&m, i, 8);
	i2osp(o, &m);

	printbuf(i, 8);
	bnu_print(&m);puts("");
	printbuf(o, 8);
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
	char *mtext = malloc(strlen(message) + 1);

	int ret = rsa_oaep_encrypt(&pkey, (uint8_t*) message, strlen(message) + 1, ctext);
	printf("%d\n", ret);
	printbuf(ctext, key.n.size * 8);

	ret = rsa_oaep_decrypt(&key, ctext, key.n.size * 8, (uint8_t*)mtext);
	printf("%s\n", mtext);
}

int main() {
	rsa_test();
}

