#include <stdio.h>

#include "sha256.h"
#include "util.h"

int main() {
	char* m = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+\n";
	uint8_t out[32];
	sha256((uint8_t*) m, 64, out);
	printbuf(out, 32);
}
