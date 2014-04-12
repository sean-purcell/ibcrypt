#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "sha256.h"
#include "util.h"

#define BK_SIZE 64

/**
 * sha256 constants
 */
const uint32_t K[64] = {
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
const uint32_t H0[8] = {
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19
};

static inline uint32_t rotr(const uint32_t x, const uint32_t n) {
	return (x >> n) | (x << ((sizeof(uint32_t) * 8) - n));
}

static inline uint32_t ch(const uint32_t x, const uint32_t y, const uint32_t z) {
	return (x & y) ^ ((~x) & z);
}

static inline uint32_t maj(const uint32_t x, const uint32_t y, const uint32_t z) {
	return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t SIG0(const uint32_t x) {
	return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static inline uint32_t SIG1(const uint32_t x) {
	return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static inline unsigned sig0(const uint32_t x) {
	return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

static inline unsigned sig1(const uint32_t x) {
	return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

/**
 * Out should be a buffer of size (message_size / BK_SIZE + 1) * BK_SIZE
 */
void pad_sha256(const uint8_t* const message, const unsigned long size, uint8_t* const out) {
	/*if(size % BK_SIZE == 0) {
		memcpy(out, message, size);
		return;
	}*/
	memset(out, 0, (size/BK_SIZE + 1) * BK_SIZE);
	memcpy(out, message, size);
	out[size] |= 1 << 7;
	
	const int k = 448 - ((size*8) % (BK_SIZE * 8)); // bits of pad
	const int kb = k/8; // bytes of pad
	
	// copy size
	const unsigned long size_bits = size * 8;
	for(int i = 0; i < 8; i++) {
		// copy 1 byte at a time, can't memcpy due to big-endian vs little-endian
		out[i + size + kb] = (size_bits >> (56 - 8 * i)) & (0xff);
	}
}

/**
 *  Schedule needs to be a buffer of size at least sizeof(uint32_t) * 64
 */
void create_message_schedule_sha256(const uint32_t* const message, uint32_t* const schedule) {
	for(int j = 0; j < 64; j++) {
		if(j < 16) {
			schedule[j] = message[j];
		} else {
			schedule[j] = sig1(schedule[j-2]) + schedule[j-7] + sig0(schedule[j-15]) + schedule[j-16];
		}
	}
}

void process_block_sha256(const uint8_t* const message, uint32_t* const state) {
	if(SHA_256_DEBUG > 1) {
		printbuf(message, 64);
	}
	// copy the message into the block
	uint32_t block[16];
	memset(block, 0, 16 * sizeof(uint32_t));
	for(int i = 0; i < 64; i++) {
		block[i/4] |= message[i] << ((3 - i % 4) * 8);
	}
	
	if(SHA_256_DEBUG > 1) {
		for(int i = 0; i < 16; i++) {
			printf("%x ", block[i]);
		}
		printf("\n");
	}
	
	uint32_t W[64]; 
	create_message_schedule_sha256(block, W);
	
	int a = state[0],
		b = state[1],
		c = state[2],
		d = state[3],
		e = state[4],
		f = state[5],
		g = state[6],
		h = state[7];
	
	if(SHA_256_DEBUG) {
		printf("init: %x %x %x %x %x %x %x %x\n", a, b, c, d, e, f, g, h);
	}
	
	for(int j = 0; j < 64; j++) {
		uint32_t T1 = h + SIG1(e) + ch(e, f, g) + K[j] + W[j],
					 T2 = SIG0(a) + maj(a, b, c);
		if(SHA_256_DEBUG > 1) {
			printf("T1: %x; T2: %x;\n", T1, T2);
			printf("h: %x; SIG1(e): %x; ch(e, f, g): %x; K[j]: %x; W[j]: %x;\n", h, SIG1(e), ch(e, f, g), K[j], W[j]);
		}
					 
		// sha256 ompression function
		{
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}
		
		if(SHA_256_DEBUG) {
			printf("t = %d %x %x %x %x %x %x %x %x\n", j, a, b, c, d, e, f, g, h);
		}
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
void hash_sha256(const uint8_t* const message, const unsigned long size, uint8_t* const out) {
	// pad the message
	const unsigned long padded_size = (size / BK_SIZE + 1) * BK_SIZE;
	uint8_t* const padded_message = (uint8_t*) malloc(padded_size);
	pad_sha256(message, size, padded_message);
	
	if(SHA_256_DEBUG) {
		printbuf(padded_message, padded_size);
	}
	
	// initialize the state
	uint32_t state[8];
	memcpy(state, H0, sizeof(uint32_t) * 8);
	
	// iterate the hash
	for(int i = 0; i < padded_size / BK_SIZE; i++) {
		process_block_sha256(padded_message + BK_SIZE * i, state);
	}
	
	// copy the state to the output
	// can't memcpy because of little-endian vs big-endian
	for(int i = 0; i < 8; i++) {
		out[i * 4 + 0] = (state[i] >> 24) & 0xff;
		out[i * 4 + 1] = (state[i] >> 16) & 0xff;
		out[i * 4 + 2] = (state[i] >>  8) & 0xff;
		out[i * 4 + 3] = (state[i] >>  0) & 0xff;
	}
	
	free(padded_message);
}
