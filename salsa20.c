#include <stdint.h>
#include <libibur/util.h>
#include <libibur/endian.h>

/* the salsa20 core hash function
 * in and out can overlap */
void salsa20_core(const uint8_t in[64], uint8_t out[64]) {
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
	((b) ^= ROT((a+d),  7));\
	((c) ^= ROT((b+a),  9));\
	((d) ^= ROT((c+b), 13));\
	((a) ^= ROT((d+c), 18));
	
	/* iterate double round 20 times */
	for(i = 0; i < 20; i += 2) {
		/* columnround */
		QROUND(x[ 0], x[ 4], x[ 8], x[12]);
		QROUND(x[ 5], x[ 9], x[13], x[ 1]);
		QROUND(x[10], x[14], x[ 2], x[ 6]);
		QROUND(x[15], x[ 3], x[ 7], x[11]);
		
		/* rowround */
		QROUND(x[ 0], x[ 1], x[ 2], x[ 3]);
		QROUND(x[ 5], x[ 6], x[ 7], x[ 4]);
		QROUND(x[10], x[11], x[ 8], x[ 9]);
		QROUND(x[15], x[12], x[13], x[ 14]);
	}
#undef ROT
#undef QROUND
	
	/* add result to orig and write to out */
	for(i = 0; i < 16; i++) {
		encle32(x[i] + o[i], &out[i * 4]);
	}
}

/* salsa20 32-byte expansion constant */
const static uint8_t sig[] = "expand 32-byte k";
/* salsa20 16-byte expansion constant */
const static uint8_t tau[] = "expand 16-byte k";

/* the salsa20expansion function 
 * ksize must be 16 or 32, otherwise
 * this function will fail silently */
void salsa20_expand(const uint8_t* const k, const uint8_t ksize, const uint8_t n[16], uint8_t out[64]) {
	if(ksize != 32 && ksize != 16)
		return;

	/* prepare input for core function */
	memcpy(&out[ 4], k, 16);
	memcpy(&out[24], n, 16);
	const uint8_t* expconst;
	if(ksize == 32) {
		memcpy(&out[44], k+16, 16);
		expconst = sig;
	} else {
		memcpy(&out[44], k, 16);
		expconst = tau;
	}
	memcpy(&out[ 0], &expconst[ 0], 4);
	memcpy(&out[20], &expconst[ 4], 4);
	memcpy(&out[40], &expconst[ 8], 4);
	memcpy(&out[60], &expconst[12], 4);
	salsa20_core(out, out);
}
