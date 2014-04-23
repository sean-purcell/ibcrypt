#include <stdio.h>
#include <time.h>

#include <libibur/util.h>

#include "sha256.h"

int main() {
	uint8_t* pw = "passwordPASSWORDpassword";
	size_t plen = 24;
	uint8_t* salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
	size_t slen = 36;
	
	uint8_t out[32];
	size_t dklen = 32;
	
	int c = 4300000;
	
	clock_t start = clock();
	pbkdf2_hmac_sha256(pw, plen, salt, slen, c, dklen, out);
	clock_t end = clock();
	float seconds = (float)(end-start) / CLOCKS_PER_SEC;
	printf("%u iterations took %f seconds.\n", c, seconds);
	printbuf(out, 32);
}
