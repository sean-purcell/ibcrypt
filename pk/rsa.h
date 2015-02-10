#ifndef IBCRYPT_PK_RSA_H
#define IBCRYPT_PK_RSA_H

/* if we're compiling inside ibcrypt, use relative directories */
#ifdef IBCRYPT_BUILD
#include "../bn/bignum.h"
#include "rsa_err.h"
#else
#include <ibcrypt/bignum.h>
#include <ibcrypt/rsa_err.h>
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
/* creates a public key from a private one */
RSA_PUBLIC_KEY pub_key(RSA_KEY *key);

int rsa_encrypt(RSA_PUBLIC_KEY *key, bignum *message, bignum *result);
int rsa_decrypt(RSA_KEY *key, bignum *ctext, bignum *result);

/* PKCS#1 v2.1 algorithms below */

/* see RFC3447 for a description of the following algorithms */
int os2ip(bignum *out, const uint8_t *const in, const size_t inLen);
int i2osp(uint8_t *out, bignum *in);

/* a mask generation function defined by RFC3447, using sha256 as the hash
 * function */
void mgf1_sha256(uint8_t *seed, size_t seedLen, size_t maskLen, uint8_t *out);

/* RSAES-OAEP encryption using MGF1 and SHA256 */
int rsa_oaep_encrypt(RSA_PUBLIC_KEY *key, uint8_t *message, size_t mlen, uint8_t *out);
int rsa_oaep_decrypt(RSA_KEY *key, uint8_t *ctext, size_t clen, uint8_t *out);

#endif

