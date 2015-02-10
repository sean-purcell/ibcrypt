#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libibur/endian.h>
#include <libibur/util.h>

#define IBCRYPT_BUILD
#include "rsa.h"
#undef IBCRYPT_BUILD
#include "../misc/zfree.h"
#include "../misc/rand.h"
#include "../hash/sha256.h"
#include "../bn/bignum.h"
#include "../bn/bignum_util.h"

/* generates a random prime that is not equal to 1 mod `e` */
int bni_rand_prime_rsa(bignum *r, const uint64_t bits, const uint64_t e, const uint32_t certainty);

/* generates an rsa key with `k` bits and a public exponent of `e`
 * returns 1 on failure, 0 on success
 */
int rsa_gen_key(RSA_KEY *key, const uint32_t k, const uint64_t e) {
	if(key == NULL) {
		return -1;
	}

	/* zero all values */
	memset(key, 0x00, sizeof(RSA_KEY));

	key->e = e;

	const uint32_t prime_bits = k / 2;

	if(bni_rand_prime_rsa(&key->p, prime_bits, e, 128) != 0) {
		return 1;
	}

	if(bni_rand_prime_rsa(&key->q, prime_bits, e, 128) != 0) {
		return 1;
	}

	if(bno_cmp(&key->p, &key->q) == 0) {
		/* if this happens, our rng must be compromised */
		return 1;
	}

	/* calculate n = pq */
	if(bno_mul(&key->n, &key->p, &key->q) != 0) {
		return 1;
	}

	/* calculate d = e^-1 (mod (p-1)(q-1)) */
	uint64_t e_mut = e;
	bignum p_m1 = BN_ZERO;
	bignum q_m1 = BN_ZERO;
	bignum t = BN_ZERO;
	bignum e_bn = { &e_mut, 1 };

	if(bno_sub(&p_m1, &key->p, &ONE) != 0) {
		return 1;
	}
	if(bno_sub(&q_m1, &key->q, &ONE) != 0) {
		return 1;
	}
	if(bno_mul(&t, &p_m1, &q_m1) != 0) {
		return 1;
	}

	if(bno_inv_mod(&key->d, &e_bn, &t) != 0) {
		return 1;
	}

	if(bnu_free(&p_m1) != 0 ||
	   bnu_free(&q_m1) != 0 ||
	   bnu_free(&t) != 0) {
		return 1;
	}

	return 0;
}

int rsa_pub_key(RSA_KEY *key, RSA_PUBLIC_KEY *pkey) {
	if(pkey == NULL || key == NULL) {
		return -1;
	}

	pkey->n = BN_ZERO;
	if(bni_cpy(&pkey->n, &key->n) != 0) {
		return CRYPTOGRAPHY_ERROR;
	}

	pkey->e = key->e;
	return 0;
}

int rsa_encrypt(RSA_PUBLIC_KEY *key, bignum *message, bignum *result) {
	if(key == NULL || message == NULL || result == NULL) {
		return -1;
	}

	if(message->size == 0) {
		/* invalid message */
		return 1;
	}
	if(bno_cmp(message, &ONE) == 0) {
		/* invalid message */
		return 1;
	}

	bignum n_m1 = BN_ZERO;
	if(bno_sub(&n_m1, &key->n, &ONE) != 0) {
		return 1;
	}
	if(bno_cmp(&n_m1, message) <= 0) {
		/* invalid message */
		return 1;
	}
	if(bnu_free(&n_m1) != 0) {
		return 1;
	}

	/* now do the actual encrypting */
	uint64_t e_mut = key->e;
	bignum e_bn = { &e_mut, 1 };

	return bno_exp_mod(result, message, &e_bn, &key->n);
}

int rsa_decrypt(RSA_KEY *key, bignum *ctext, bignum *result) {
	if(key == NULL || ctext == NULL || result == NULL) {
		return -1;
	}

	if(ctext->size == 0) {
		/* invalid message */
		return 1;
	}
	if(bno_cmp(ctext, &ONE) == 0) {
		/* invalid message */
		return 1;
	}

	bignum n_m1 = BN_ZERO;
	if(bno_sub(&n_m1, &key->n, &ONE) != 0) {
		return 1;
	}
	if(bno_cmp(&n_m1, ctext) <= 0) {
		/* invalid message */
		return 1;
	}
	if(bnu_free(&n_m1) != 0) {
		return 1;
	}

	/* now do the actual decrypting */
	return bno_exp_mod(result, ctext, &key->d, &key->n);
}

int os2ip(bignum *out, const uint8_t *const in, const size_t inLen) {
	if(out == NULL || in == NULL) {
		return -1;
	}
	if(inLen > 0xffffffffULL * 8) {
		return TOO_LONG; /* too big */
	}

	/* zero the output */
	if(bnu_resize(out, 0) != 0) {
		return CRYPTOGRAPHY_ERROR;
	}

	const uint32_t size = (inLen + 7) / 8;
	if(bnu_resize(out, size) != 0) {
		return CRYPTOGRAPHY_ERROR;
	}

	size_t i;
	for(i = 0; i < inLen; i++) {
		size_t block = (inLen - i - 1) / 8;
		size_t offset = ((inLen - i - 1) % 8) * 8;
		out->d[block] |= ((uint64_t) in[i]) << offset;
	}

	return 0;
}

int i2osp(uint8_t *out, bignum *in) {
	if(out == NULL || in == NULL) {
		return -1;
	}

	size_t outLen = ((size_t) in->size) * 8;
	size_t i;
	for(i = 0; i < outLen; i++) {
		size_t block = (outLen - i - 1) / 8;
		size_t offset = ((outLen - i - 1) % 8) * 8;
		out[i] = (in->d[block] & ((uint64_t)0xff << offset)) >> offset;
	}

	return 0;
}

void mgf1_sha256(uint8_t *seed, size_t seedLen, size_t maskLen, uint8_t *out) {
	SHA256_CTX base, ctrhash;

	sha256_init(&base);
	sha256_update(&base, seed, seedLen);

	uint8_t ctrbuf[4];
	uint8_t hashbuf[32];

	uint64_t ctr;
	for(ctr = 0; ctr < maskLen; ctr+=32) {
		memcpy(&ctrhash, &base, sizeof(SHA256_CTX));
		encbe32(ctr / 32, ctrbuf);
		sha256_update(&ctrhash, ctrbuf, 4);
		sha256_final(&ctrhash, hashbuf);
		if(maskLen - ctr < 32) {
			memcpy(&out[ctr], hashbuf, maskLen - ctr);
		} else {
			memcpy(&out[ctr], hashbuf, 32);
		}
	}

	memsets(&base, 0, sizeof(SHA256_CTX));
	memsets(&ctrhash, 0, sizeof(SHA256_CTX));
	memsets(ctrbuf, 0, 4);
	memsets(hashbuf, 0, 32);
}

/* when l is the empty string, this is the value of lHash */
const uint8_t lhash[] = {0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55};

int rsa_oaep_encrypt(RSA_PUBLIC_KEY *key, uint8_t *message, size_t mlen, uint8_t *out) {
	if(key == NULL || message == NULL || out == NULL) {
		return -1;
	}

	const size_t k = (size_t)key->n.size * 8;
	const size_t hlen = 32;
	uint8_t seed[hlen];
	uint8_t *mask;
	uint8_t *em;
	uint8_t *db;
	bignum m_bn;
	bignum c_bn;

	int ret;

	if(k - 2 * hlen - 2 < mlen) {
		return TOO_LONG;
	}

	/* do stuff involving the masks first, as in case of error it does not
	 * need to be kept secure */
	if(cs_rand(seed, hlen) != 0) {
		return CRYPTOGRAPHY_ERROR;
	}

	if((mask = malloc(k - hlen - 1)) == NULL) {
		return MALLOC_FAIL;
	}

	/* calculate dbMask = MGF(seed, k - hLen - 1) */
	mgf1_sha256(seed, hlen, k - hlen - 1, mask);

	/* now initialize the string to be encrypted */
	if((em = malloc(k - 1)) == NULL) {
		return MALLOC_FAIL;
	}

	/* from now on we have to clean up memory after any failures */
	/* em[hlen:] is all DB = lhash || PS || 0x01 || M */
	db = em + hlen;
	memcpy(db, lhash, hlen);
	/* PS is a padding string of zeroes */
	memset(db + hlen, 0x00, k - 2 * hlen - mlen - 2);
	/* there is then one byte of value 0x01 */
	db[k - 2 - hlen - mlen] = 0x01;
	/* then message */
	memcpy(&db[k - hlen - mlen - 1], message, mlen);

	/* now apply the mask to it */
	xor_bytes(db, mask, k - hlen - 1, db);

	/* now we can repurpose mask to encode the seed mask */
	mgf1_sha256(db, k - hlen - 1, hlen, mask);
	/* xor it into em */
	xor_bytes(seed, mask, hlen, em);

	m_bn = BN_ZERO;
	c_bn = BN_ZERO;
	/* now convert to a big integer */
	if((ret = os2ip(&m_bn, em, k - 1)) != 0) {
		goto err;
	}

	/* encrypt */
	if((ret = rsa_encrypt(key, &m_bn, &c_bn)) != 0) {
		goto err;
	}

	/* convert back */
	if((ret = i2osp(out, &c_bn)) != 0) {
		goto err;
	}

	/* encryption is officially done, clean up */
	ret = 0;

err:
	/* free mask and em, zero seed */
	zfree(mask, k - hlen - 1);
	zfree(em, k - 1);
	memsets(seed, 0x00, hlen);

	/* free the bignums */
	/* an error here is still an error as it is a possible leak of
	 * sensitive data */
	ret = ret == 0 ? bnu_free(&m_bn) : ret;
	ret = ret == 0 ? bnu_free(&c_bn) : ret;

	return ret;
}

int rsa_oaep_decrypt(RSA_KEY *key, uint8_t *ctext, size_t clen, uint8_t *out) {
	if(key == NULL || ctext == NULL || out == NULL) {
		return -1;
	}

	const size_t k = (size_t)key->n.size * 8;
	const size_t hlen = 32;
	bignum c_bn = BN_ZERO;
	bignum m_bn = BN_ZERO;
	uint8_t *em = NULL;
	uint8_t *db = NULL;
	uint8_t *mask = NULL;
	uint8_t seed[32];
	size_t message_start;

	int ret;

	/* nothing critical yet */
	if((ret = os2ip(&c_bn, ctext, clen)) != 0) {
		return ret;
	}

	/* now sensitive information is contained in our buffers, so we have
	 * to clean up */
	if((ret = rsa_decrypt(key, &c_bn, &m_bn)) != 0) {
		goto err;
	}

	if((em = malloc(k)) == NULL) {
		ret = MALLOC_FAIL;
		goto err;
	}

	if((ret = i2osp(em, &m_bn)) != 0) {
		goto err;
	}
	db = em + hlen + 1;

	if((mask = malloc(k - hlen - 1)) == NULL) {
		ret = MALLOC_FAIL;
		goto err;
	}

	/* calculate seed mask = MGF1(maskedDB, k - hlen - 1) */
	mgf1_sha256(db, k - hlen - 1, hlen, mask);

	/* calculate seed */
	xor_bytes(em + 1, mask, hlen, seed);

	/* calculate dbMask */
	mgf1_sha256(seed, hlen, k - hlen - 1, mask);

	/* unmask db */
	xor_bytes(db, mask, k - hlen - 1, db);

	/* find the start of the message */
	for(message_start = hlen; message_start < k - hlen - 1 &&
		db[message_start] == 0x00; message_start++) {}

	uint8_t valid = 0;
	valid |= memcmp_ct(db, lhash, 32);
	valid |= em[0];
	valid |= !(message_start != k - hlen - 1 && db[message_start] == 1);

	/* if valid is non-zero this is not a valid message */
	if(valid != 0) {
		ret = CRYPTOGRAPHY_ERROR;
		goto err;
	}

	memcpy(out, &db[message_start], k - hlen - 1 - message_start);

	ret = 0;
err:
	ret = ret == 0 ? bnu_free(&c_bn) : ret;
	ret = ret == 0 ? bnu_free(&m_bn) : ret;
	if(em) zfree(em, k);
	if(mask) zfree(mask, k - hlen - 1);
	memsets(seed, 0x00, hlen);

	return ret;
}

