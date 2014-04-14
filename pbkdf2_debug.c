#include "sha256.h"
#include "util.h"

int main() {
	uint8_t* p = (uint8_t*) "passwordPASSWORDpassword";
	uint8_t* s = (uint8_t*) "saltSALTsaltSALTsaltSALTsaltSALTsalt";
	uint32_t c = 65536;
	uint8_t out[40];
	pbkdf2_hmac_sha256(p, 24, s, 36, c, 40, out);
	printbuf(out, 40);
}