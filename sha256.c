#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "sha256.h"
#include "util.h"

/**
 * sha256 constants
 */
static const uint32_t K[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))

/* sha256 operations */
#define ch(x, y, z)	((x & (y ^ z)) ^ z)                          
#define maj(x, y, z)	((x & (y | z)) | (y & z))
#define shr(x, n)	(x >> n)
#define rotr(x, n)	((x >> n) | (x << (32 - n)))
#define S0(x)		(rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
#define S1(x)		(rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))
#define s0(x)		(rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3))
#define s1(x)		(rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10))

/**
 *  Schedule needs to be a buffer of size at least sizeof(uint32_t) * 64
 */
static void create_message_schedule_sha256(const uint32_t* const message, uint32_t* const schedule) {
	for(int j = 0; j < 64; j++) {
		if(j < 16) {
			schedule[j] = message[j];
		} else {
			schedule[j] = s1(schedule[j-2]) + schedule[j-7] + s0(schedule[j-15]) + schedule[j-16];
		}
	}
}

static void process_block_sha256(SHA256_CTX* ctx) {
	/* copy the message into the block */
	uint32_t block[16];
	memset(block, 0, 16 * sizeof(uint32_t));
	for(int i = 0; i < 64; i++) {
		block[i/4] |= ctx->buf[i] << ((3 - i % 4) * 8);
	}
	
	uint32_t W[64]; 
	create_message_schedule_sha256(block, W);
	
	uint32_t a = ctx->state[0],
		 b = ctx->state[1],
		 c = ctx->state[2],
		 d = ctx->state[3],
		 e = ctx->state[4],
		 f = ctx->state[5],
		 g = ctx->state[6],
		 h = ctx->state[7];
	
	for(int j = 0; j < 64; j++) {
		// sha256 compression function
		uint32_t T1 = h + S1(e) + ch(e, f, g) + K[j] + W[j],
		         T2 = S0(a) + maj(a, b, c);

		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	// update state
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

/**
 * Initial sha256 state
 */
static const uint32_t H0[8] = {
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19
};

void sha256_init(SHA256_CTX* ctx) {
	/* initialize sha256 state */
	memcpy(&(ctx->state), H0, sizeof(uint32_t) * 8);
	ctx->count = 0;
}

void sha256_update(SHA256_CTX* ctx, const uint8_t* message, size_t msize) {
	while(msize > 0) {
		const int bufoff = ctx->count % 64;
		if(bufoff + msize <= 64) {
			memcpy(ctx->buf + bufoff, message, msize);
			
			/* increment counters by amount read into buf */
			ctx->count += msize;
			message += msize;
			msize = 0;
		} else {
			const int space = 64 - bufoff;
			memcpy(ctx->buf + bufoff, message, space);
			
			/* increment counters by amount read into buf */
			ctx->count += space;
			msize -= space;
			message += space;
		}
		
		/* test if the buffer has been filled, if so process block */
		if(ctx->count % 64 == 0) {
			process_block_sha256(ctx);
		}
	}
}

void sha256_final(SHA256_CTX* ctx, uint8_t sum[32]) {
	int bufoff = ctx->count % 64;
	ctx->buf[bufoff] = 0x80;
	if(bufoff >= 56) { /* not enough space to write pad and length */
		/* finish this block, process, then do another pad block */
		memset(ctx->buf + bufoff + 1, 0, 64 - bufoff - 1);
		process_block_sha256(ctx);
		bufoff = 0;
	}
	
	/* bytes of pad */
	int pad = 55 - bufoff;
	memset(ctx->buf + bufoff + 1, 0, pad);
	
	const uint64_t lbits = ctx->count * 8; /* length of message in bits */
	
	/* copy length of message into last 8 bytes, big endian */
	for(int i = 0; i < 8; i++) {
		ctx->buf[56 + i] = (lbits >> (56 - i * 8)) & 0xff;
	}
	process_block_sha256(ctx);
	
	/* copy the state out into the sum buffer */
	for(int i = 0; i < 8; i++) {
		sum[i * 4 + 0] = (ctx->state[i] >> 24) & 0xff;
		sum[i * 4 + 1] = (ctx->state[i] >> 16) & 0xff;
		sum[i * 4 + 2] = (ctx->state[i] >>  8) & 0xff;
		sum[i * 4 + 3] = (ctx->state[i] >>  0) & 0xff;
	}
	
	/* clean the context */
	memset(ctx, 0, sizeof(SHA256_CTX));
}

void sha256(const uint8_t* message, size_t osize, uint8_t* out) {
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, message, osize);
	sha256_final(&ctx, out);
	
	/* no need to zero ctx as final does it */
}

void hmac_sha256_init(HMAC_SHA256_CTX* ctx, const uint8_t* _key, size_t keylen) {
	const uint8_t* key = _key;
	uint8_t khash[32];
	uint8_t pad[64];
	
	/* if the key is longer than 64 bytes, the used key is sha256(key) */
	if(keylen > 64) {
		sha256(key, keylen, khash);
		key = khash;
		keylen = 32;
	}
	
	sha256_init(&(ctx->octx));
	sha256_init(&(ctx->ictx));
	
	/* update the inner and outer contexts with the padded keys */
	memset(pad, 0x36, 64);
	xor_bytes(pad, key, keylen, pad);
	
	sha256_update(&(ctx->ictx), pad, 64);
	
	memset(pad, 0x5c, 64);
	xor_bytes(pad, key, keylen, pad);
	
	sha256_update(&(ctx->octx), pad, 64);
	
	/* clean stack */
	memset(khash, 0, 32);
	memset(pad, 0, 64);
}

void hmac_sha256_update(HMAC_SHA256_CTX* ctx, uint8_t* message, size_t mlen) {
	/* feed the data into the inner context */
	sha256_update(&(ctx->ictx), message, mlen);
}

void hmac_sha256_final(HMAC_SHA256_CTX* ctx, uint8_t mac[32]) {
	/* compute the inner hash */
	uint8_t ihash[32];
	sha256_final(&(ctx->ictx), ihash);
	
	/* update outer hash */
	sha256_update(&(ctx->octx), ihash, 32);
	
	/* compute final value */
	sha256_final(&(ctx->octx), mac);
	
	/* clean context unecessary as final was called on ictx and octx */
}

void hmac_sha256(uint8_t* key, size_t keylen, uint8_t* message, size_t len, uint8_t* out) {
	HMAC_SHA256_CTX ctx;
	hmac_sha256_init(&ctx, key, keylen);
	hmac_sha256_update(&ctx, message, len);
	hmac_sha256_final(&ctx, out);
}

// PBKDF2_HMAC_SHA256

// dkLen and hlen are in bytes
void pbkdf2_hmac_sha256(uint8_t* pass, size_t plen, uint8_t* salt, size_t saltLen, uint32_t c, size_t dkLen, uint8_t* out) {
	/* in case dkLen is not a multiple of 32 */
	const uint32_t sections = (dkLen + 31)/32;
	/* 32 bit buffer to store integer counter */
	uint8_t count_buf[4];
	/* previous hash */
	uint8_t prev[32];
	/* partial key */
	uint8_t pkey[32];
	
	/* context with pass as key before processing anything 
	   not actually used for computation, just as holder so
	   we don't have to recompute init every iteration */
	HMAC_SHA256_CTX Pctx;
	/* context for computation use */
	HMAC_SHA256_CTX ctx;
	
	hmac_sha256_init(&Pctx, pass, plen);
	
	for(uint32_t i = 1; i <= sections; i++) {
		/* init ctx with password */
		memcpy(&ctx, &Pctx, sizeof(HMAC_SHA256_CTX));
		
		for(int x = 0; x < 4; x++) {
			count_buf[x] = (i >> (24 - x * 8)) & 0xff;
		}
		
		/* update hmac with salt and count */
		hmac_sha256_update(&ctx, salt, saltLen);
		hmac_sha256_update(&ctx, count_buf, 4);
		
		hmac_sha256_final(&ctx, prev);
		
		memcpy(pkey, prev, 32);
		
		/* begin iterations */
		for(int u = 0; u < c - 1; u++) {
			/* init ctx with password */
			memcpy(&ctx, &Pctx, sizeof(HMAC_SHA256_CTX));
			
			/* compute next iteration */
			hmac_sha256_update(&ctx, prev, 32);
			hmac_sha256_final(&ctx, prev);
			
			/* xor result into partial key */
			xor_bytes(prev, pkey, 32, pkey);
		}
		
		/* copy derived key to output */
		int clen = min(32, dkLen);
		memcpy(out, pkey, clen);
		out += 32;
		dkLen -= 32;
	}
	
	/* final was never called on Pctx */
	memset(&Pctx, 0, sizeof(HMAC_SHA256_CTX));
}
