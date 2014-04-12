#include <stdio.h>
#include <stdint.h>

#include "sha256.c"
#include "util.c"

int main() {
	{
		uint8_t* word = (uint8_t*)"abc";
	
		uint8_t hash[32];
		hash_sha256(word, 3, hash);
		printbuf(hash, 32);
	}
	{
		uint8_t* word = (uint8_t*)"";
	
		uint8_t hash[32];
		hash_sha256(word, 0, hash);
		printbuf(hash, 32);
	}
	{
		uint8_t* word = (uint8_t*)"The quick brown fox jumps over the lazy dog";
	
		uint8_t hash[32];
		hash_sha256(word, 43, hash);
		printbuf(hash, 32);
	}
	{
		uint8_t* word = (uint8_t*)"The quick brown fox jumps over the lazy dog.";
	
		uint8_t hash[32];
		hash_sha256(word, 44, hash);
		printbuf(hash, 32);
	}
	{
		uint8_t* word = (uint8_t*)"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";
	
		uint8_t hash[32];
		hash_sha256(word, 234, hash);
		printbuf(hash, 32);
	}
}
