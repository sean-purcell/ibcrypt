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

	if(k < 4) {
		return TOO_SHORT;
	}

	/* zero all values */
	memset(key, 0x00, sizeof(RSA_KEY));

	key->e = e;
	key->bits = k;

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
	pkey->bits = key->bits;
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

int os2ip(bignum *out, uint8_t *in, size_t inlen) {
	if(out == NULL || in == NULL) {
		return -1;
	}
	if(inlen > 0xffffffffULL * 8) {
		return TOO_LONG; /* too big */
	}

	/* zero the output */
	if(bnu_resize(out, 0) != 0) {
		return CRYPTOGRAPHY_ERROR;
	}

	const uint32_t size = (inlen + 7) / 8;
	if(bnu_resize(out, size) != 0) {
		return CRYPTOGRAPHY_ERROR;
	}

	size_t i;
	for(i = 0; i < inlen; i++) {
		size_t block = (inlen - i - 1) / 8;
		size_t offset = ((inlen - i - 1) % 8) * 8;
		out->d[block] |= ((uint64_t) in[i]) << offset;
	}

	return 0;
}

int i2osp(uint8_t *out, size_t outlen, bignum *in) {
	if(out == NULL || in == NULL) {
		return -1;
	}

	size_t i = 0;
	if(outlen > in->size * 8) {
		memset(out, 0x00, outlen - in->size * 8);
		i = outlen - in->size * 8;
	}
	for(; i < outlen; i++) {
		size_t block = (outlen - i - 1) / 8;
		size_t offset = ((outlen - i - 1) % 8) * 8;
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

int rsa_oaep_encrypt(RSA_PUBLIC_KEY *key, uint8_t *message, size_t mlen, uint8_t *out, size_t outlen) {
	if(key == NULL || message == NULL || out == NULL) {
		return -1;
	}

	const size_t k = (key->bits - 1) / 8 + 1;
	const size_t hlen = 32;
	uint8_t seed[hlen];
	uint8_t *mask;
	uint8_t *em;
	uint8_t *db;
	bignum m_bn;
	bignum c_bn;

	int ret;

	/* message is too long to encrypt */
	if(k - 2 * hlen - 2 < mlen) {
		return TOO_LONG;
	}

	/* output buffer is too small */
	if(outlen < k) {
		return TOO_SHORT;
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
	if((em = malloc(k)) == NULL) {
		return MALLOC_FAIL;
	}

	/* from now on we have to clean up memory after any failures */
	/* em[hlen:] is all DB = lhash || PS || 0x01 || M */
	db = em + hlen + 1;
	memcpy(db, lhash, hlen);
	/* PS is a padding string of zeroes */
	memset(db + hlen, 0x00, k - 2 * hlen - mlen - 2);
	/* there is then one byte of value 0x01 */
	db[k - 2 - hlen - mlen] = 0x01;
	/* then message */
	memcpy(&db[k - hlen - 1 - mlen], message, mlen);

	/* now apply the mask to it */
	xor_bytes(db, mask, k - hlen - 1, db);

	/* now we can repurpose mask to encode the seed mask */
	mgf1_sha256(db, k - hlen - 1, hlen, mask);
	/* xor it into em */
	xor_bytes(seed, mask, hlen, em + 1);

	em[0] = 0x00;

	m_bn = BN_ZERO;
	c_bn = BN_ZERO;
	/* now convert to a big integer */
	if((ret = os2ip(&m_bn, em, k)) != 0) {
		goto err;
	}

	/* encrypt */
	if((ret = rsa_encrypt(key, &m_bn, &c_bn)) != 0) {
		goto err;
	}

	/* convert back */
	if((ret = i2osp(out, outlen, &c_bn)) != 0) {
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

int rsa_oaep_decrypt(RSA_KEY *key, uint8_t *ctext, size_t clen, uint8_t *out, size_t outlen) {
	if(key == NULL || ctext == NULL || out == NULL) {
		return -1;
	}

	const size_t k = (key->bits - 1) / 8 + 1;
	const size_t hlen = 32;
	bignum c_bn = BN_ZERO;
	bignum m_bn = BN_ZERO;
	uint8_t *em = NULL;
	uint8_t *db = NULL;
	uint8_t *mask = NULL;
	uint8_t seed[hlen];
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

	if((ret = i2osp(em, k, &m_bn)) != 0) {
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

	message_start++;

	/* prevent buffer overflows */
	if(outlen < k - hlen - 1 - message_start) {
		ret = TOO_SHORT;
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

int rsa_pss_sign(RSA_KEY *key, uint8_t *message, size_t mlen, uint8_t *out, size_t outlen) {
	if(key == NULL || message == NULL || out == NULL) {
		return -1;
	}

	const size_t k = (key->bits - 1) / 8 + 1;
	const size_t emlen = (key->bits - 2) / 8 + 1;
	const size_t hlen = 32;
	const size_t slen = hlen;
	SHA256_CTX ctx;
	uint8_t mhash[hlen];
	uint8_t salt[slen];
	uint8_t zeroes[8];
	uint8_t *em = NULL;
	bignum em_bn = BN_ZERO;
	bignum s_bn = BN_ZERO;

	int ret;

	if(outlen < k) {
		/* avoid buffer overflows */
		return TOO_SHORT;
	}

	if(emlen < hlen + slen + 2) {
		/* key too small to sign */
		return CRYPTOGRAPHY_ERROR;
	}

	/* allocate space for em */
	if((em = malloc(emlen)) == NULL) {
		return MALLOC_FAIL;
	}

	/* generate salt, as we can still exit without cleanup if this fails */
	if(cs_rand(salt, slen) != 0) {
		return CRYPTOGRAPHY_ERROR;
	}

	sha256_init(&ctx);
	sha256_update(&ctx, message, mlen);
	sha256_final(&ctx, mhash);

	/* calculate H = sha256(0x00 00 00 00 00 00 00 00 || mhash || salt) */
	memset(zeroes, 0x00, 8);

	sha256_init(&ctx);
	sha256_update(&ctx, zeroes, 8);
	sha256_update(&ctx, mhash, hlen);
	sha256_update(&ctx, salt, slen);
	sha256_final(&ctx, &em[emlen - hlen - 1]);

	mgf1_sha256(&em[emlen - hlen - 1], hlen, emlen - hlen - 1, em);

	/* xor in 0x01 and salt */
	em[emlen - slen - hlen - 2] ^= 0x01;
	xor_bytes(&em[emlen - slen - hlen - 1], salt, slen, &em[emlen - slen - hlen - 1]);
	em[emlen - 1] = 0xbc;

	em[0] &= ((uint8_t) 0xff) >> (8 * emlen - (key->bits - 1));

	if((ret = os2ip(&em_bn, em, emlen)) != 0) {
		goto err;
	}

	if((ret = rsa_decrypt(key, &em_bn, &s_bn)) != 0) {
		goto err;
	}

	if((ret = i2osp(out, outlen, &s_bn)) != 0) {
		goto err;
	}

	ret = 0;
err:
	memsets(mhash, 0, hlen);
	memsets(salt, 0, slen);
	memsets(&ctx, 0, sizeof(SHA256_CTX));
	bnu_free(&s_bn);
	bnu_free(&em_bn);
	if(em) zfree(em, emlen);

	return ret;
}

int rsa_pss_verify(RSA_PUBLIC_KEY *key, uint8_t *sig, size_t siglen, uint8_t *message, size_t mlen, int *valid) {
	if(key == NULL || sig == NULL || message == NULL || valid == NULL) {
		return -1;
	}

	const size_t k = (key->bits - 1) / 8 + 1;
	const size_t emlen = (key->bits - 2) / 8 + 1;
	const size_t hlen = 32;
	const size_t slen = hlen;
	SHA256_CTX ctx;
	uint8_t hash[hlen];
	uint8_t zeroes[8];
	uint8_t *em = NULL;
	uint8_t *mask = NULL;
	bignum em_bn = BN_ZERO;
	bignum s_bn = BN_ZERO;

	int ret;

	*valid = 0;

	if((em = malloc(emlen)) == NULL) {
		return MALLOC_FAIL;
	}

	if((mask = malloc(emlen - hlen - 1)) == NULL) {
		ret = MALLOC_FAIL;
		goto err;
	}

	if((ret = os2ip(&s_bn, sig, siglen)) != 0) {
		/* cleanup is non-necessary here, but no harm */
		goto err;
	}

	if((ret = rsa_encrypt(key, &s_bn, &em_bn)) != 0) {
		goto err;
	}

	if((ret = i2osp(em, emlen, &em_bn)) != 0) {
		goto err;
	}

	mgf1_sha256(&em[emlen - hlen - 1], hlen, emlen - hlen - 1, mask);

	xor_bytes(em, mask, emlen - hlen - 1, em);

	sha256_init(&ctx);
	sha256_update(&ctx, message, mlen);
	sha256_final(&ctx, hash);

	memset(zeroes, 0x00, 8);

	sha256_init(&ctx);
	sha256_update(&ctx, zeroes, 8);
	sha256_update(&ctx, hash, hlen);
	sha256_update(&ctx, &em[emlen - hlen - slen - 1], slen);
	sha256_final(&ctx, hash);

	xor_bytes(&em[emlen - hlen - 1], hash, hlen, &em[emlen - hlen - 1]);
	em[emlen - hlen - slen - 2] ^= 0x01;
	em[emlen - 1] ^= 0xbc;
	em[0] &= ((uint8_t) 0xff) >> (emlen * 8 - (key->bits - 1));
	memset(&em[emlen - hlen - slen - 1], 0x00, slen);

	size_t i;
	uint8_t val = 0;
	for(i = 0; i < emlen; i++) {
		val |= (em[i]);
	}

	if(val) {
		*valid = 0;
	} else {
		*valid = 1;
	}

	ret = 0;

err:
	memsets(&ctx, 0x00, sizeof(SHA256_CTX));
	memsets(hash, 0x00, hlen);
	if(em) zfree(em, emlen);
	if(mask) zfree(mask, emlen - hlen - 1);
	bnu_free(&em_bn);
	bnu_free(&s_bn);

	return ret;
}


