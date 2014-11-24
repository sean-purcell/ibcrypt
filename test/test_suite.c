#include <stdio.h>
#include <time.h>

#include <libibur/util.h>
#include <libibur/test.h>

void aes_tests();
void sha256_tests();
void aes_mode_tests();
void salsa20_tests();
void chacha_tests();
void scrypt_tests();
void bignum_tests();

void (*suite[])() = {
	aes_tests,
	sha256_tests,
	aes_mode_tests,
	salsa20_tests,
	chacha_tests,
	scrypt_tests,
	bignum_tests,
};

const char* names[] = {
	"AES",
	"SHA256",
	"AES modes",
	"SALSA20",
	"CHACHA",
	"SCRYPT",
	"BIGNUM",
};

int main(int argc, char** argv) {
	for(int i = 0; i < sizeof(suite)/sizeof(suite[0]); i++) {
		clock_t start = clock();
		(*suite[i])();
		clock_t end = clock();
		float seconds = (float)(end-start) / CLOCKS_PER_SEC;
		printf("%s done.  %f seconds elapsed.\n", 
			names[i], seconds);
	}
}
