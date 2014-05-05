#include <stdint.h>
#include <libibur/util.h>
#include <libibur/endian.h>

/* the salsa20 core hash function
 * in and out can overlap */
void salsa20_core(uint8_t in[64], uint8_t out[64]) {
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
