#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "scrypt.h"
#include "sha256.h"
#include "util.h"

#define SCRYPT_USE_MMAP

static uint64_t integerify(uint32_t* B, uint32_t r) {
	uint64_t val = 0;
	uint32_t* x = B + (2 * r - 1) * 16;
	val |= (uint64_t)(x[0]) <<  0;
	val |= (uint64_t)(x[1]) << 32;
	return val;
}

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))

static void salsa20_8(uint32_t B[16]) {
	uint32_t x[16];
	
	memcpy(x, B, 64);
	
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
		B[i] += x[i];
	}
}

static void blockmix(uint32_t* B, uint32_t r, uint32_t* Bout) {
	uint64_t i = 0;
	
	uint32_t* X;
	uint32_t* Y;
	
	/* 1: X <- B_{2r-1} */
	X = B + (2 * r-1) * 16;
	
	/* 2: for i = 0 to 2r - 1 do */
	for(i = 0; i < 2*r; i++) {
		Y = Bout + ((i/2) * 16 + (i%2) * 16 * r);
		
		/* 3: X <- H(X xor Bi) */
		xor_bytes((uint8_t*) X, (uint8_t*)(B + i * 16), 64, (uint8_t*) Y);
		salsa20_8(Y);

		/* 4: Yi <- X */
		/* 6: B' <- (Y0, Y2, ..., Y2r-2, Y1, Y3, ..., Y2r-1) */
		X = Y;
		
	/* 5: end for */
	}
	
//	memcpy(Bout, Y, 128 * r);
}
	
/* smix = ROMix_BlockMix_salsa20/8, r(B, N) */
static void smix(uint8_t* B, uint64_t N, uint32_t r, uint32_t* V, uint32_t* X, uint32_t* Y) {
	uint64_t i, j;
	
	/* 1: X <- B */
	
	for(i = 0; i < 32 * r; i++) {
		X[i] = B[i * 4];
		X[i] |= (uint32_t)(B[i * 4 + 1]) <<  8;
		X[i] |= (uint32_t)(B[i * 4 + 2]) << 16;
		X[i] |= (uint32_t)(B[i * 4 + 3]) << 24;
	}
	
	/* 2: for i = 0 to N - 1 do */
	for(i = 0; i < N; i+=2) {
		/* 3: Vi <- X */
		memcpy(V + i * 32 * r, X, 128 * r);
		
		/* 4: X <- BlockMix_salsa20_8(X) */
		blockmix(X, r, Y);
		
		/* 3: Vi <- X */
		memcpy(V + (i + 1) * 32 * r, Y, 128 * r);
		
		/* 4: X <- BlockMix_salsa20_8(X) */
		blockmix(Y, r, X);
		
	/* 5: end for */
	}
	
	/* 6: for i = 0 to N - 1 do */
	for(i = 0; i < N; i+=2) {
		/* 7: j <- Integerify(X) mod N */
		j = integerify(X, r) % N;
		
		/* 8: X <- H(X xor Vj) */
		xor_bytes(X, V + j * 32 * r, 128 * r, X);
		blockmix(X, r, Y);
		
		/* 7: j <- Integerify(X) mod N */
		j = integerify(Y, r) % N;
		
		/* 8: X <- H(X xor Vj) */
		xor_bytes(Y, V + j * 32 * r, 128 * r, Y);
		blockmix(Y, r, X);
		
	/* 9: end for */
	}
	
	/* 10: B' <- X */
	for(i = 0; i < 32 * r; i++) {
		B[i * 4 + 0] = (X[i] >>  0) & 0xff;
		B[i * 4 + 1] = (X[i] >>  8) & 0xff;
		B[i * 4 + 2] = (X[i] >> 16) & 0xff;
		B[i * 4 + 3] = (X[i] >> 24) & 0xff;
	}
}

int scrypt(uint8_t* pass, uint32_t plen, uint8_t* salt, uint32_t slen,
	uint64_t N, uint32_t r, uint32_t p, size_t dkLen, uint8_t* out) {
	
	uint8_t* B;
	uint32_t* V;
	uint32_t* X;
	uint32_t* Y;
	
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
	if((B = mmap(NULL, pMFlen, 
	PROT_READ | PROT_WRITE,
	MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		/* map failed */
		goto err0;
	}
	
	if((V = mmap(NULL, 128 * r * N + 128 * r * 2,
	PROT_READ | PROT_WRITE,
	MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		/* map failed */
		goto err1;
	}
#else
	if((B = malloc(pMFlen)) == NULL) {
		/* could not allocate the memory */
		errno = ENOMEM;
		goto err0;
	}
	
	/* malloc space for V and blockmix work buffer */
	if((V = malloc(128 * r * N + 128 * r * 2)) == NULL) {
		/* could not allocate the memory */
		errno = ENOMEM;
		goto err1;
	}
#endif
	
	X = V + 32 * r * N;
	Y = V + 32 * r * N + 32 * r;
	
	/* 1: (B0, ..., Bp-1) <- PBKDFhmac_sha256(pass, salt, 1, p * MFlen) */
	pbkdf2_hmac_sha256(pass, plen, salt, slen, 1, pMFlen, B);
	
	
	/* 2: for i = 0 to p - 1 do */
	for(uint32_t i = 0; i < p; i++) {
		/* 3: Bi = MF(Bi, N) */
		smix(B + i * r * 128, N, r, V, X, Y);
	/* 4: end for */
	}
	
	/* 5: DK <- PBKDF2hmac_sha256(pass, B, 1, dkLen) */
	pbkdf2_hmac_sha256(pass, plen, B, pMFlen, 1, dkLen, out);
	
#ifdef SCRYPT_USE_MMAP
	munmap(B, pMFlen);
	munmap(V, 128 * r * N + 128 * r * 2);
#else
	free(B);
	free(V);
#endif
	
	/* success! */
	return 0;
	
#ifdef SCRYPT_USE_MMAP
err1:
	munmap(B, pMFlen);
err0:
	/* failed */
	return -1;
#else
err1:
	free(B);
err0:
	/* failed */
	return -1;
#endif
}
