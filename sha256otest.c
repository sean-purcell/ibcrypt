#include <string.h>
#include <time.h>
#include <stdio.h>

#include "sha256.h"
#include "util.h"

int main() {
	const uint32_t iters = 65536;
	{
		uint8_t buf[96];
		memset(buf, 0, 96);
		clock_t start = clock();
		for(int i = 0; i < iters; i++) {
			sha256(buf, 96, buf);
		}
		clock_t end = clock();
		float seconds = (float)(end-start) / CLOCKS_PER_SEC;
		printf("%u iterations of sha256 took %f seconds.\n", iters, seconds);
		printbuf(buf, 96);
	}
	{
		uint8_t buf[96];
		memset(buf, 0, 96);
		clock_t start = clock();
		for(int i = 0; i < iters; i++) {
			sha256(buf, 96, buf);
		}
		clock_t end = clock();
		float seconds = (float)(end-start) / CLOCKS_PER_SEC;
		printf("%u iterations of sha256 took %f seconds.\n", iters, seconds);
		printbuf(buf, 96);
	}
	{
		uint8_t* p = (uint8_t*) "passwordPASSWORDpassword";
		uint8_t* s = (uint8_t*) "saltSALTsaltSALTsaltSALTsaltSALTsalt";
		uint32_t c = iters;
		uint8_t out[64];
		clock_t start = clock();
		pbkdf2_hmac_sha256(p, 24, s, 36, c, 64, out);
		clock_t end = clock();
		float seconds = (float)(end-start) / CLOCKS_PER_SEC;
		printf("%u iterations of pbkdf2 hmac sha256 took %f seconds.\n", iters, seconds);
		printbuf(out, 64);
	}
}

