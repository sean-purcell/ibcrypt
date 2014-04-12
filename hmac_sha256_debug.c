#include <stdio.h>
#include <stdint.h>

#include "hmac_sha256.h"
#include "util.h"

int main() {
	const unsigned char* t = (const unsigned char*) "";
	uint8_t buf[32];
	hmac_sha256(t, 0, t, 0, buf);
	printbuf(buf, 32);
}