#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "sha256.h"
#include "util.h"

static uint64_t integerify(uint8_t* B, uint32_t r) {
	uint64_t val = 0;
	uint8_t* x = B + (2 * r - 1) * 64;
	val |= (uint64_t)(x[0]) <<  0;
	val |= (uint64_t)(x[1]) <<  8;
	val |= (uint64_t)(x[2]) << 16;
	val |= (uint64_t)(x[3]) << 24;
	val |= (uint64_t)(x[4]) << 32;
	val |= (uint64_t)(x[5]) << 40;
	val |= (uint64_t)(x[6]) << 48;
	val |= (uint64_t)(x[7]) << 56;
	
	return val;
}

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))

static void salsa20_8(uint8_t B[64]) {
	uint32_t x[16];
	uint32_t ble[16];
	
	for(int i = 0; i < 16; i++) {
		x[i] = B[i * 4];
		x[i] |= (uint32_t)(B[i * 4 + 1]) <<  8;
		x[i] |= (uint32_t)(B[i * 4 + 2]) << 16;
		x[i] |= (uint32_t)(B[i * 4 + 3]) << 24;
	}
	
	memcpy(ble, x, 16 * sizeof(uint32_t));
	
	for (int i = 0; i < 8; i += 2) {
		/* columns */
		x[ 4] ^= ROTL(x[ 0]+x[12], 7);
		x[ 8] ^= ROTL(x[ 4]+x[ 0], 9);
		x[12] ^= ROTL(x[ 8]+x[ 4],13);
		x[ 0] ^= ROTL(x[12]+x[ 8],18);

		x[ 9] ^= ROTL(x[ 5]+x[ 1], 7);
		x[13] ^= ROTL(x[ 9]+x[ 5], 9);
		x[ 1] ^= ROTL(x[13]+x[ 9],13);
		x[ 5] ^= ROTL(x[ 1]+x[13],18);

		x[14] ^= ROTL(x[10]+x[ 6], 7);
		x[ 2] ^= ROTL(x[14]+x[10], 9);
		x[ 6] ^= ROTL(x[ 2]+x[14],13);
		x[10] ^= ROTL(x[ 6]+x[ 2],18);

		x[ 3] ^= ROTL(x[15]+x[11], 7);
		x[ 7] ^= ROTL(x[ 3]+x[15], 9);
		x[11] ^= ROTL(x[ 7]+x[ 3],13);
		x[15] ^= ROTL(x[11]+x[ 7],18);

		/* rows */
		x[ 1] ^= ROTL(x[ 0]+x[ 3], 7);
		x[ 2] ^= ROTL(x[ 1]+x[ 0], 9);
		x[ 3] ^= ROTL(x[ 2]+x[ 1],13);
		x[ 0] ^= ROTL(x[ 3]+x[ 2],18);

		x[ 6] ^= ROTL(x[ 5]+x[ 4], 7);
		x[ 7] ^= ROTL(x[ 6]+x[ 5], 9);
		x[ 4] ^= ROTL(x[ 7]+x[ 6],13);
		x[ 5] ^= ROTL(x[ 4]+x[ 7],18);

		x[11] ^= ROTL(x[10]+x[ 9], 7);
		x[ 8] ^= ROTL(x[11]+x[10], 9);
		x[ 9] ^= ROTL(x[ 8]+x[11],13);
		x[10] ^= ROTL(x[ 9]+x[ 8],18);

		x[12] ^= ROTL(x[15]+x[14], 7);
		x[13] ^= ROTL(x[12]+x[15], 9);
		x[14] ^= ROTL(x[13]+x[12],13);
		x[15] ^= ROTL(x[14]+x[13],18);
	}
	
	for(int i = 0; i < 16; i++) {
		ble[i] += x[i];
		
		B[i * 4] = ble[i] & 0xff;
		B[i * 4 + 1] = (ble[i] >>  8) & 0xff;
		B[i * 4 + 2] = (ble[i] >> 16) & 0xff;
		B[i * 4 + 3] = (ble[i] >> 24) & 0xff;
	}
}

static void blockmix(uint8_t* B, uint32_t r, uint8_t* Bout) {
	uint8_t X[64];
	uint8_t* out = malloc(128 * r);
	//printbuf(B, r * 128);
	uint64_t i = 0;
	
	/* 1: X <- B_{2r-1} */
	memcpy(X, B + (2 * r - 1) * 64, 64);
	
	/* 2: for i = 0 to 2r - 1 do */
	for(i = 0; i < 2*r; i++) {
		/* 3: X <- H(X xor Bi) */
		//printbuf(B + i * 64, 64);
		xor_bytes(X, B + i * 64, 64, X);
		//printbuf(X, 64);
		salsa20_8(X);
		//printbuf(X, 64);

		/* 4: Yi <- X */
		/* 6: B' <- (Y0, Y2, ..., Y2r-2, Y1, Y3, ..., Y2r-1) */
		memcpy(out + ((i/2) * 64) + ((i%2) * r * 64), X, 64);
		
	/* 5: end for */
	}
	
	memcpy(Bout, out, 128 * r);
	free(out);
}
	
/* smix = ROMix_BlockMix_salsa20/8, r(B, N) */
static int smix(uint8_t* Bi, uint64_t N, uint32_t r) {
	uint8_t* X;
	uint8_t* V;
	uint64_t i, j;
//	if((X = malloc(128 * r)) == NULL) {
//		/* malloc failed */
//		goto err0;
//	}
	
	if((V = malloc(128 * r * N)) == NULL) {
		/* malloc failed */
		goto err0;
	}
	
	/* 1: X <- B */
	X = Bi;
	
	/* 2: for i = 0 to N - 1 do */
	for(i = 0; i < N; i++) {
		/* 3: Vi <- X */
		memcpy(V + i * 128 * r, X, 128 * r);
		
		//printbuf(X, 128 * r);
		/* 4: X <- BlockMix_salsa20_8(X) */
		blockmix(X, r, X);
		//printbuf(X, 128 * r);
		
	/* 5: end for */
	}
	
	/* 6: for i = 0 to N - 1 do */
	for(i = 0; i < N; i++) {
		/* 7: j <- Integerify(X) mod N */
		j = integerify(X, r) % N;
		
		/* 8: X <- H(X xor Vj) */
		xor_bytes(X, V + j * 128 * r, 128 * r, X);
		blockmix(X, r, X);
		
	/* 9: end for */
	}
	
	/* 10: B' <- X */
	/* nop, because B = X */
	
	free(V);
	
	/* success */
	return 0;
	
err0:
	/* failure */
	return -1;
}

int scrypt(uint8_t* pass, uint32_t plen, uint8_t* salt, uint32_t slen,
	uint64_t N, uint32_t r, uint32_t p, size_t dkLen, uint8_t* out) {
	
	uint8_t* B;
	
	const size_t pMFlen = 128 * p * r;
	
	/* check params */
#if SIZE_MAX > UINT32_MAX
	if(dkLen > (((size_t)(1) << 32) - 1) * 32) {
		errno = EFBIG;
		goto err0;
	}
#endif
	if((uint64_t)(r) * (uint64_t)(p) >= (1 << 30)) {
		errno = EFBIG;
		goto err0;
	}
	
	if(N & N-1) {
		errno = EINVAL;
		goto err0;
	}
	
#ifdef SCRYPT_USE_MMAP
	// TODO: implement
#else
	if((B = malloc(pMFlen)) == NULL) {
		/* could not allocate the memory */
		// TODO: find err code for this
		errno = ENOMEM;
		goto err0;
	}
#endif
	
	/* 1: (B0, ..., Bp-1) <- PBKDFhmac_sha256(pass, salt, 1, p * MFlen) */
	pbkdf2_hmac_sha256(pass, plen, salt, slen, 1, pMFlen, B);
	
	
	/* 2: for i = 0 to p - 1 do */
	for(uint32_t i = 0; i < p; i++) {
		/* 3: Bi = MF(Bi, N) */
		//printf("before%d\n", i);
		//printbuf(B + i * r * 128, 128 * r);
		smix(B + i * r * 128, N, r);
		//printf("after %d\n", i);
		//printbuf(B + i * r * 128, 128 * r);
	/* 4: end for */
	}
	
	/* 5: DK <- PBKDF2hmac_sha256(pass, B, 1, dkLen) */
	pbkdf2_hmac_sha256(pass, plen, B, pMFlen, 1, dkLen, out);
	
	free(B);
	
	/* success! */
	return 0;
err0:
	/* Failed */
	return -1;
}
