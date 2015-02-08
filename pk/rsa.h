#ifndef IBCRYPT_PK_RSA_H
#define IBCRYPT_PK_RSA_H

/* if we're compiling inside ibcrypt, use relative directories */
#ifdef IBCRYPT_BUILD
#include "../bn/bignum.h"
#else
#include <ibcrypt/bignum.h>
#endif

typedef struct {
	bignum p;
	bignum q;
	bignum n;
	bignum d;
	uint64_t e;
} RSA_KEY;

typedef struct {
	bignum n;
	uint64_t e;
} RSA_PUBLIC_KEY;

int gen_rsa_key(RSA_KEY *key, const uint32_t k, const uint64_t e);

int rsa_encrypt(RSA_PUBLIC_KEY *key, bignum *message, bignum *result);
int rsa_decrypt(RSA_KEY *key, bignum *ctext, bignum *result);

#endif

