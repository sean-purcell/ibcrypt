#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libibur/endian.h>

#include "chacha.h"

#ifdef CHACHA_DEBUG
#include <libibur/util.h>
#endif

/* the chacha core hash function
 * in and out can overlap */
void chacha_core(const uint8_t in[64], uint8_t out[64]) {
	uint32_t x[16];
	uint32_t o[16];
	uint8_t i;
	for(i = 0; i < 16; i++) {
		x[i] = decle32(&in[i*4]);
	}
	/* store original */
	memcpy(o, x, 16 * sizeof(uint32_t));
	
#define ROT(x, n) (((x) << n) | ((x) >> (32 - n)))
#define QROUND(a,b,c,d) \
	(a) += (b); (d) = ROT((d) ^ (a), 16);\
	(c) += (d); (b) = ROT((b) ^ (c), 12);\
	(a) += (b); (d) = ROT((d) ^ (a),  8);\
	(c) += (d); (b) = ROT((b) ^ (c),  7);;
	
	/* iterate double round 20 times */
	for(i = 0; i < 20; i += 2) {
		/* columnround */
		QROUND(x[ 0], x[ 4], x[ 8], x[12]);
		QROUND(x[ 1], x[ 5], x[ 9], x[13]);
		QROUND(x[ 2], x[ 6], x[10], x[14]);
		QROUND(x[ 3], x[ 7], x[11], x[15]);
		
		/* diaground */
		QROUND(x[ 0], x[ 5], x[10], x[15]);
		QROUND(x[ 1], x[ 6], x[11], x[12]);
		QROUND(x[ 2], x[ 7], x[ 8], x[13]);
		QROUND(x[ 3], x[ 4], x[ 9], x[14]);
	}
#undef ROT
#undef QROUND
	
	/* add result to orig and write to out */
	for(i = 0; i < 16; i++) {
		encle32(x[i] + o[i], &out[i * 4]);
	}
}

/* chacha 32-byte expansion constant */
const static uint8_t sig[] = "expand 32-byte k";
/* chacha 16-byte expansion constant */
const static uint8_t tau[] = "expand 16-byte k";

/* the chachaexpansion function 
 * ksize must be 16 or 32, otherwise
 * this function will fail silently */
void chacha_expand(const uint8_t* const k, const int ksize, const uint8_t n[16], uint8_t out[64]) {
	if(ksize != 32 && ksize != 16)
		return;

	/* prepare input for core function */
	const uint8_t* expconst;
	if(ksize == 32) {
		memcpy(&out[16], k, 32);
		expconst = sig;
	} else {
		memcpy(&out[16], k, 16);
		memcpy(&out[32], k, 16);
		expconst = tau;
	}
	memcpy(out, expconst, 16);
	memcpy(&out[48], n, 16);
	
	chacha_core(out, out);
}

/* initialize a chacha context
 * returns NULL on failure */
CHACHA_CTX* init_chacha(const uint8_t* key, const int ksize, const uint64_t nonce) {
	CHACHA_CTX* ctx;
	
	if(ksize != 16 && ksize != 32) {
		/* unacceptable */
		goto err0;
	}
	
	if((ctx = malloc(sizeof(CHACHA_CTX))) == NULL) {
		errno = ENOMEM;
		goto err0;
	}

	ctx->ksize = ksize;
	memcpy(ctx->key, key, ksize);
	/* for 16 byte keys 0 the rest */
	memset(&ctx->key[ksize], 0x00, 32 - ksize);
	
	ctx->nonce = nonce;
	ctx->count = 0;

	return ctx;

err0:
	/* failure! */
	return NULL;
}

/* encrypt/decrypt a section */
void stream_chacha(CHACHA_CTX* ctx, const uint8_t* const in, uint8_t* const out, const uint64_t len) {
	uint64_t i;
	/* the n value to pass when expanding new stream block */
	uint8_t n[16];
	encle64(ctx->nonce, &n[8]);
	
	for(i = 0; i < len; i++) {
		if(ctx->count % 64 == 0) {
			encle64(ctx->count / 64, &n[0]);
			chacha_expand(ctx->key, ctx->ksize, n, ctx->stream);
#ifdef CHACHA_DEBUG
			printbuf(n, 16);
#endif
		}
		out[i] = in[i] ^ ctx->stream[ctx->count%64];
		ctx->count++;
	}
}

/* frees an initialized chacha context */
void free_chacha(CHACHA_CTX* ctx) {
	memset(ctx, 0x00, sizeof(CHACHA_CTX));
	free(ctx);
}

/* convenience functions */
int chacha_enc(const uint8_t* key, const int ksize, const uint64_t nonce, const uint8_t* const in, uint8_t* const out, const uint64_t len) {
	CHACHA_CTX* ctx = init_chacha(key, ksize, nonce);
	if(ctx == NULL) {
		return 1;
	}
	
	stream_chacha(ctx, in, out, len);
	free_chacha(ctx);
	return 0;
}

int chacha_dec(const uint8_t* key, const int ksize, const uint64_t nonce, const uint8_t* const in, uint8_t* const out, const uint64_t len) {
	return chacha_enc(key, ksize, nonce, in, out, len);
}
