#include <stdio.h>
#include <time.h>

#include "sha256_test.h"
#include "aes_test.h"
#include "test.h"

extern void aes_tests();
extern void sha256_tests();

void (*suite[])() = {
	aes_tests,
	sha256_tests
};

const char* names[] = {
	"AES",
	"SHA256"
};

int main() {
	for(int i = 0; i < sizeof(suite)/sizeof(suite[0]); i++) {
		clock_t start = clock();
		(*suite[i])();
		clock_t end = clock();
		float seconds = (float)(end-start) / CLOCKS_PER_SEC;
		printf("%s done.  %u tests completed.  %f seconds elapsed.\n", names[i], count_tests(), seconds);
		reset_tests();
	}
}