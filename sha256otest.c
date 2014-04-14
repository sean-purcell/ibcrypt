#include <string.h>
#include <time.h>
#include <stdio.h>

#include "sha256.h"
#include "util.h"

int main() {
	const uint32_t iters = 65536;
	{ // normal test
		uint8_t buf[96];
		memset(buf, 0, 96);
		clock_t start = clock();
		for(int i = 0; i < iters * 2; i++) {
			sha256(buf, 96, buf);
		}
		clock_t end = clock();
		float seconds = (float)(end-start) / CLOCKS_PER_SEC;
		printf("%u iterations took %f seconds.\n", iters, seconds);
		printbuf(buf, 96);
	}
	// {
// 		uint8_t buf[96];
// 		memset(buf, 0, 96);
// 		clock_t start = clock();
// 		for(int i = 0; i < iters * 2; i++) {
// 			sha256_fast(buf, 96, buf);
// 		}
// 		clock_t end = clock();
// 		float seconds = (float)(end-start) / CLOCKS_PER_SEC;
// 		printf("%u iterations took %f seconds.\n", iters, seconds);
// 		printbuf(buf, 96);
// 	}
	{
		uint8_t* p = (uint8_t*) "passwordPASSWORDpassword";
		uint8_t* s = (uint8_t*) "saltSALTsaltSALTsaltSALTsaltSALTsalt";
		uint32_t c = iters;
		uint8_t out[32];
		clock_t start = clock();
		pbkdf2_hmac_sha256(p, 32, s, 32, c, 32, out);
		clock_t end = clock();
		float seconds = (float)(end-start) / CLOCKS_PER_SEC;
		printf("%u iterations took %f seconds.\n", iters, seconds);
		printbuf(out, 32);
	}
}

