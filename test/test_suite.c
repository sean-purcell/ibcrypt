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
	"AES_MODES",
	"SALSA20",
	"CHACHA",
	"SCRYPT",
	"BIGNUM",
};

void run_test(int num) {
	clock_t start = clock();
	(*suite[num])();
	clock_t end = clock();
	float seconds = (float)(end-start) / CLOCKS_PER_SEC;
	printf("%s done.  %f seconds elapsed.\n", names[num], seconds);
}

int main(int argc, char** argv) {
	const int num_tests = sizeof(suite) / sizeof(suite[0]);
	if(argc > 1) {
		for(int i = 1; i < argc; i++) {
			/* find test to run */
			int test;
			for(test = 0; test < num_tests; test++) {
				if(strcmp(names[test], argv[i]) == 0) {
					break;
				}
			}
			if(test == num_tests) {
				printf("test %s not found.\n", argv[i]);
			} else {
				run_test(test);
			}
		}
	} else {
		for(int i = 0; i < num_tests; i++) {
			run_test(i);
		}
	}
}
