#include <stdio.h>
#include "aes.c"

void size128Test() {
	unsigned char key_bytes[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	AES_KEY aes_key;
	memset(&aes_key, 0, (16 * (MAX_RNDS + 1)));
	if(create_AES_key(key_bytes, 128, &aes_key)) {
		printf("ERROR");
		return -1;
	}
	for(int i = 0; i < 16 * (MAX_RNDS + 1); i++) {
		if(aes_key.rd_key[i] < 16) {
			printf("0");
		}
		printf("%x ", aes_key.rd_key[i]);
		if(i % 16 == 15) {
			printf("\n");
		}
	}
}

void size192Test() {
	unsigned char key_bytes[24] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	AES_KEY aes_key;
	memset(&aes_key, 0, (16 * (MAX_RNDS + 1)));
	if(create_AES_key(key_bytes, 192, &aes_key)) {
		printf("ERROR");
		return -1;
	}
	for(int i = 0; i < 16 * (MAX_RNDS + 1); i++) {
		if(aes_key.rd_key[i] < 16) {
			printf("0");
		}
		printf("%x ", aes_key.rd_key[i]);
		if(i % 16 == 15) {
			printf("\n");
		}
	}
}