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
	size_t bits;
} RSA_KEY;

typedef struct {
	bignum n;
	uint64_t e;
	size_t bits;
} RSA_PUBLIC_KEY;

int rsa_gen_key(RSA_KEY *key, const uint32_t k, const uint64_t e);
/* creates a public key from a private one */
int rsa_pub_key(RSA_KEY *key, RSA_PUBLIC_KEY *pkey);

int rsa_encrypt(RSA_PUBLIC_KEY *key, bignum *message, bignum *result);
int rsa_decrypt(RSA_KEY *key, bignum *ctext, bignum *result);

/* returns the size in bytes of the cipher text using a given modulus */
size_t ctext_size(bignum *n);
/* returns the size in bytes of the signature text using a given modulus */
size_t sig_size(bignum *n);

/* PKCS#1 v2.1 algorithms below */

/* see RFC3447 for a description of the following algorithms */
int os2ip(bignum *out, uint8_t *in, size_t inLen);
int i2osp(uint8_t *out, size_t outlen, bignum *in);

/* a mask generation function defined by RFC3447, using sha256 as the hash
 * function */
void mgf1_sha256(uint8_t *seed, size_t seedLen, size_t maskLen, uint8_t *out);

/* RSAES-OAEP encryption using MGF1 and SHA256 */
int rsa_oaep_encrypt(RSA_PUBLIC_KEY *key, uint8_t *message, size_t mlen, uint8_t *out, size_t outlen);
int rsa_oaep_decrypt(RSA_KEY *key, uint8_t *ctext, size_t clen, uint8_t *out, size_t outlen);

/* RSASSA-PSS signatures and verifcations, signs the sha256 hash of message */
int rsa_pss_sign(RSA_KEY *key, uint8_t *message, size_t mlen, uint8_t *out, size_t outlen);
int rsa_pss_verify(RSA_PUBLIC_KEY *key, uint8_t *sig, size_t siglen, uint8_t *message, size_t mlen, int *valid);

#endif

