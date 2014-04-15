#include <stdio.h>

#include "sha256.h"
#include "util.h"

int main() {
	char* m = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456\n";
	//char* m = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456\n";
	uint8_t out[32];
	sha256((uint8_t*) m, 60, out);
	printbuf(out, 32);
}
