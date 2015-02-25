#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define IBCRYPT_BUILD
#include "rsa_util.h"
#include "rsa.h"
#undef IBCRYPT_BUILD

#include "../bn/bignum.h"
#include "../libibur/util.h"

int main() {
	uint8_t buf[528];
	memset(buf, 0, 528);
	RSA_KEY key;
	RSA_PUBLIC_KEY pkey;
	rsa_gen_key(&key, 2048, 65537);
	rsa_pub_key(&key, &pkey);

	printf("n:\n");bnu_print(&pkey.n);puts("");
	printf("e:\n%llu\n", pkey.e);

	if(rsa_pubkey2wire(&pkey, buf, 528) != 0) {
		fprintf(stderr, "%d :C\n", __LINE__);
	}
	printbuf(buf, 272);
	if(rsa_wire2pubkey(buf, 528, &pkey) != 0) {
		fprintf(stderr, "%d :C\n", __LINE__);
	}

	printf("n:\n");bnu_print(&pkey.n);puts("");
	printf("e:\n%llu\n", pkey.e);

	printf("n:\n");bnu_print(&key.n);puts("");
	printf("p:\n");bnu_print(&key.p);puts("");
	printf("q:\n");bnu_print(&key.q);puts("");
	printf("d:\n");bnu_print(&key.d);puts("");
	printf("e:\n%llu\n", key.e);

	if(rsa_prikey2wire(&key, buf, 528) != 0) {
		fprintf(stderr, "%d :C\n", __LINE__);
	}
	printbuf(buf, 528);
	if(rsa_wire2prikey(buf, 528, &key) != 0) {
		fprintf(stderr, "%d :C\n", __LINE__);
	}

	printf("n:\n");bnu_print(&key.n);puts("");
	printf("p:\n");bnu_print(&key.p);puts("");
	printf("q:\n");bnu_print(&key.q);puts("");
	printf("d:\n");bnu_print(&key.d);puts("");
	printf("e:\n%llu\n", key.e);
}

