#ifndef IBCRYPT_PK_RSA_UTIL_H
#define IBCRYPT_PK_RSA_UTIL_H

#include <stdint.h>

#ifdef IBCRYPT_BUILD
#include "rsa.h"
#else
#include <ibcrypt/rsa.h>
#endif

/* converts keys to and from wire format, compatible with each other */

/* out must be big enough to hold the key */
int rsa_pubkey2wire(RSA_PUBLIC_KEY *key, uint8_t *out, size_t outlen);
int rsa_prikey2wire(RSA_KEY *key, uint8_t *out, size_t outlen);
int rsa_wire2pubkey(uint8_t *in, size_t inlen, RSA_PUBLIC_KEY *key);
int rsa_wire2prikey(uint8_t *in, size_t inlen, RSA_KEY *key);

size_t rsa_pubkey_bufsize(uint64_t bits);
size_t rsa_prikey_bufsize(uint64_t bits);

#endif

