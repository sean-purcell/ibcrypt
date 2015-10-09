#include <stdint.h>

#include <libibur/endian.h>

#include "../bn/bignum.h"

#define IBCRYPT_BUILD
#include "rsa.h"
#include "rsa_util.h"
#undef IBCRYPT_BUILD

/* converts keys to and from wire format, compatible with each other */

/* out must be big enough to hold the key */
int rsa_pubkey2wire(RSA_PUBLIC_KEY *key, uint8_t *out, size_t outlen) {
	if(outlen < 8 + (key->bits + 7) / 8 + 8) {
		return 1;
	}

	encbe64(key->bits, out);
	
	if(i2osp(&out[8], (key->bits + 7) / 8, &key->n) != 0) {
		goto error;
	}

	encbe64(key->e, &out[(key->bits + 7) / 8 + 8]);

	return 0;

error:
	memset(out, 0, outlen);
	return 1;
}

int rsa_prikey2wire(RSA_KEY *key, uint8_t *out, size_t outlen) {
	size_t p_len = ((key->bits / 2) + 7) / 8;
	if(outlen < 8 + 2 * p_len + (key->bits + 7) / 8 + 8) {
		return 1;
	}

	encbe64(key->bits, out);

	if(i2osp(&out[8], p_len, &key->p) != 0) {
		goto error;
	}
	if(i2osp(&out[p_len + 8], p_len, &key->q) != 0) {
		goto error;
	}

	if(i2osp(&out[p_len * 2 + 8], (key->bits + 7) / 8, &key->d) != 0) {
		goto error;
	}

	encbe64(key->e, &out[p_len * 2 + (key->bits + 7) / 8 + 8]);

	return 0;

error:
	memset(out, 0, outlen);
	return 1;
}

int rsa_wire2pubkey(uint8_t *in, size_t inlen, RSA_PUBLIC_KEY *key) {
	key->n = BN_ZERO;
	key->bits = decbe64(in);
	if(inlen < (key->bits + 7) / 8 + 8) {
		return 1;
	}

	if(os2ip(&key->n, &in[8], (key->bits + 7) / 8) != 0) {
		goto error;
	}

	key->e = decbe64(&in[8 + (key->bits + 7) / 8]);

	return 0;

error:
	memset(key, 0, sizeof(RSA_PUBLIC_KEY));
	return 1;
}

int rsa_wire2prikey(uint8_t *in, size_t inlen, RSA_KEY *key) {
	memset(key, 0, sizeof(RSA_KEY));

	key->bits = decbe64(in);
	size_t p_len = ((key->bits / 2) + 7) / 8;

	if(inlen < 8 + 2 * p_len + (key->bits + 7) / 8 + 8) {
		goto error;
	}

	if(os2ip(&key->p, &in[8], p_len) != 0) {
		goto error;
	}
	if(os2ip(&key->q, &in[8 + p_len], p_len) != 0) {
		goto error;
	}
	if(os2ip(&key->d, &in[8 + 2 * p_len], (key->bits + 7) / 8) != 0) {
		goto error;
	}

	key->e = decbe64(&in[p_len * 2 + (key->bits + 7) / 8 + 8]);

	if(bno_mul(&key->n, &key->p, &key->q) != 0) {
		goto error;
	}

	return 0;
error:
	memset(key, 0, sizeof(RSA_KEY));
	return 1;
}

int rsa_wire_prikey2pubkey(uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
	uint64_t bits = decbe64(in);
	size_t p_len = ((bits / 2) + 7) / 8;
	int ret = 0;

	if(inlen < rsa_prikey_bufsize(bits) || outlen < rsa_pubkey_bufsize(bits)) {
		return -1;
	}

	bignum n = BN_ZERO, p = BN_ZERO, q = BN_ZERO;
	if(os2ip(&p, &in[8], p_len) != 0) {
		goto error;
	}
	if(os2ip(&q, &in[8+p_len], p_len) != 0) {
		goto error;
	}

	if(bno_mul(&n, &p, &q) != 0) {
		goto error;
	}

	memcpy(out, in, 8);
	i2osp(&out[8], (bits + 7) / 8, &n);
	memcpy(&out[rsa_pubkey_bufsize(bits) - 8],
		&in[rsa_prikey_bufsize(bits) - 8], 8);

	goto cleanup;

error:
	ret = 1;
cleanup:
	ret |= bnu_free(&n);
	ret |= bnu_free(&p);
	ret |= bnu_free(&q);

	return ret;
}

size_t rsa_pubkey_bufsize(uint64_t bits) {
	return (bits + 7) / 8 + 16;
}

size_t rsa_prikey_bufsize(uint64_t bits) {
	return ((bits / 2) + 7) / 8 * 2 + (bits + 7) / 8 + 16;
}

