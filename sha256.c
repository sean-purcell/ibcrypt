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

#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))
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

static void process_block_sha256(const uint8_t* const message, uint32_t* const state) {
	// copy the message into the block
	uint32_t block[16];
	memset(block, 0, 16 * sizeof(uint32_t));
	for(int i = 0; i < 64; i++) {
		block[i/4] |= message[i] << ((3 - i % 4) * 8);
	}
	
	uint32_t W[64]; 
	create_message_schedule_sha256(block, W);
	
	uint32_t a = state[0],
		b = state[1],
		c = state[2],
		d = state[3],
		e = state[4],
		f = state[5],
		g = state[6],
		h = state[7];
	
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
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

/**
 * Out should be a buffer of size 32
 */
void sha256(const uint8_t* message, const uint64_t osize, uint8_t* const out) {
	uint64_t size = osize;
	uint8_t buf[64];
	
	// initialize the state
	uint32_t state[8];
	memcpy(state, H0, sizeof(uint32_t) * 8);
	// iterate the hash
	while(1) {
		if(size >= 64) {
			process_block_sha256(message, state);
			message += 64;
			size -= 64;
		} else {
			memcpy(buf, message, size);
			// pad
			buf[size] = 0x80;
			if(size < 56) {				
				uint64_t bp = 56 - 1 - size; // bytes of pad
				memset(buf + size + 1, 0, bp);
			} else {
				memset(buf + size + 1, 0, 64 - size - 1);
				process_block_sha256(buf, state);
				memset(buf, 0, 56);
			}
			const uint64_t size_bits = osize * 8;
			for(int i = 0; i < 8; i++) {
				// copy 1 byte at a time, can't memcpy due to big-endian vs little-endian
				buf[56 + i] = (size_bits >> (56 - 8 * i)) & (0xff);
			}
			process_block_sha256(buf, state);
			goto out;
		}
	}
	
	out:;
	// copy the state to the output
	// can't memcpy because of little-endian vs big-endian
	for(int i = 0; i < 8; i++) {
		out[i * 4 + 0] = (state[i] >> 24) & 0xff;
		out[i * 4 + 1] = (state[i] >> 16) & 0xff;
		out[i * 4 + 2] = (state[i] >>  8) & 0xff;
		out[i * 4 + 3] = (state[i] >>  0) & 0xff;
	}
}

// HMAC_SHA256

const uint8_t ipad[64] = {0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36};
const uint8_t opad[64] = {0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c};

static void adjust_key(const uint8_t* const key, const uint32_t keylen, uint8_t* const out) {
	memset(out, 0, 64);
	if(keylen <= 64) {
		memcpy(out, key, keylen);
	} else {
		sha256(key, keylen, out);
	}
}

void hmac_sha256(const uint8_t* const key, const uint32_t keylen, const uint8_t* const message, uint32_t len, uint8_t* const out) {
	uint8_t adjkey[64];
	adjust_key(key, keylen, adjkey);
	
	uint8_t* inner_hash_buf = (uint8_t*) malloc(len + 64); // this could be any size
	xor_bytes(adjkey, ipad, 64, inner_hash_buf);
	memcpy(inner_hash_buf + 64, message, len);
	
	uint8_t outer_hash_buf[96]; // this is just a 64 byte key plus a 32 byte hash
	xor_bytes(adjkey, opad, 64, outer_hash_buf);
	sha256(inner_hash_buf, len + 64, outer_hash_buf + 64);
	
	sha256(outer_hash_buf, 96, out);
}

// PBKDF2_HMAC_SHA256

// dkLen and hlen are in bytes
void pbkdf2_hmac_sha256(const uint8_t* const pass, const uint32_t plen, const uint8_t* salt, const uint32_t saltLen, const uint32_t c, uint32_t dkLen, uint8_t* out) {
	
	memset(out, 0, dkLen);
	
	const uint32_t sections = (dkLen + 31)/32; // in case dkLen is not a multiple of 32
	
	for(uint32_t i = 1; i <= sections; i++) {
		uint8_t prev[max(32, saltLen + 4)];
		memcpy(prev, salt, saltLen);
		
		for(int x = 0; x < 4; x++) {
			prev[saltLen + x] = (i >> (24 - x * 8)) & 0xff;
		}
		
		for(int u = 0; u < c; u++) {
			hmac_sha256(pass, plen, prev, (u == 0 ? saltLen + 4 : 32), prev);
			xor_bytes(out, prev, min(32, dkLen), out);
		}
		out += 32;
		dkLen -= 32;
	}
}
