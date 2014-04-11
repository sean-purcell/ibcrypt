#include <stdio.h>
#include "sha256.c"
#include "util.c"

int main() {
	unsigned char* word = (unsigned char*)"abc";
	
	unsigned char out[64];
	
	
	unsigned char hash[32];
	hash_sha256(word, 3, hash);
	printbuf(hash, 32);
	
	unsigned int i = 0x80000000;
	printf("%x\n", i >> 1);
}
