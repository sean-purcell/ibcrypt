#include <stdio.h>
#include <stdint.h>

#include "hmac_sha256.h"
#include "util.h"

int main() {
	{const unsigned char* t = (const unsigned char*) "";
	uint8_t buf[32];
	hmac_sha256(t, 0, t, 0, buf);
	printbuf(buf, 32);}
	{const unsigned char* m = (const unsigned char*) "The quick brown fox jumps over the lazy dog";
	const unsigned char* k = (const unsigned char*) "key";
	uint8_t buf[32];
	hmac_sha256(k, 3, m, 43, buf);
	printbuf(buf, 32);}
}