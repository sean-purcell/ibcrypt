#include <stdio.h>
#include "sha256.c"
#include "util.c"

int main() {
	{
		unsigned char* word = (unsigned char*)"abc";
	
		unsigned char hash[32];
		hash_sha256(word, 3, hash);
		printbuf(hash, 32);
	}
	{
		unsigned char* word = (unsigned char*)"";
	
		unsigned char hash[32];
		hash_sha256(word, 0, hash);
		printbuf(hash, 32);
	}
	{
		unsigned char* word = (unsigned char*)"The quick brown fox jumps over the lazy dog";
	
		unsigned char hash[32];
		hash_sha256(word, 43, hash);
		printbuf(hash, 32);
	}
	{
		unsigned char* word = (unsigned char*)"The quick brown fox jumps over the lazy dog.";
	
		unsigned char hash[32];
		hash_sha256(word, 44, hash);
		printbuf(hash, 32);
	}
	{
		unsigned char* word = (unsigned char*)"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";
	
		unsigned char hash[32];
		hash_sha256(word, 234, hash);
		printbuf(hash, 32);
	}
}
