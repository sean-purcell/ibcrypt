#include "stdint.h"
#include "string.h"

#include "pbkdf2.h"
#include "util.h"

#define max(a, b) (a > b ? a : b)

// dkLen and hlen are in bytes
void pbkdf2(void (*prf)(const uint8_t* const key, const uint32_t keylen, const uint8_t* const message, uint32_t len, uint8_t* const out),
	const uint32_t hlen, const uint8_t* const pass, const uint32_t plen, const uint8_t* salt, const uint32_t saltLen, const uint32_t c, const uint32_t dkLen, uint8_t* const out) {
	
	memset(out, 0, dkLen);
	
	const uint32_t sections = (dkLen + hlen - 1)/hlen; // in case dkLen is not a multiple of hlen
	
	for(uint32_t i = 1; i <= sections; i++) {
		uint8_t prev[max(hlen, saltLen + 4)];
		memcpy(prev, salt, saltLen);
		
		for(int x = 0; x < 4; x++) {
			prev[saltLen + x] = (i >> (24 - x * 8)) & 0xff;
		}
		
		for(int u = 0; u < c; u++) {
			prf(pass, plen, prev, (u == 0 ? saltLen + 4 : hlen), prev);
			xor_bytes(out + ((i-1) * hlen), prev, hlen, out + ((i-1) * hlen));
		}
	}
}