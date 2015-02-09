#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define IBCRYPT_BUILD
#include "rsa.h"
#undef IBCRYPT_BUILD
#include "../bn/bignum.h"
#include "../bn/bignum_util.h"

/* generates a random prime that is not equal to 1 mod `e` */
int bni_rand_prime_rsa(bignum *r, const uint64_t bits, const uint64_t e, const uint32_t certainty);

/* generates an rsa key with `k` bits and a public exponent of `e`
 * returns 1 on failure, 0 on success
 */
int gen_rsa_key(RSA_KEY *key, const uint32_t k, const uint64_t e) {
	if(key == NULL) {
		return 1;
	}

	/* zero all values */
	memset(key, 0x00, sizeof(RSA_KEY));

	key->e = e;

	const uint32_t prime_bits = k / 2;

	if(bni_rand_prime_rsa(&key->p, prime_bits, e, 128) != 0) {
		return 1;
	}

	if(bni_rand_prime_rsa(&key->p, prime_bits, e, 128) != 0) {
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

int rsa_encrypt(RSA_PUBLIC_KEY *key, bignum *message, bignum *result) {
	if(key == NULL || message == NULL || result == NULL) {
		return 1;
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
		return 1;
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
		return 1;
	}
	if(inLen > 0xffffffffULL * 8) {
		return 1; /* too big */
	}

	/* zero the output */
	if(bnu_resize(out, 0) != 0) {
		return 1;
	}

	const uint32_t size = (inLen + 7) / 8;
	if(bnu_resize(out, size) != 0) {
		return 1;
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
		return 1;
	}

	size_t outLen = ((size_t) in->size) * 8;
	size_t i;
	for(i = 0; i < outLen; i++) {
		size_t block = (outLen - i - 1) / 8;
		size_t offset = ((outLen - i - 1) % 8) * 8;
		out[i] = (in->d[block] & (0xff << offset)) >> offset;
	}

	return 0;
}

