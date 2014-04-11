#include <stdio.h>
#include "aes.c"
#include "util.c"

void size128Test() {
	unsigned char key_bytes[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	AES_KEY aes_key;
	memset(&aes_key, 0, (16 * (MAX_RNDS + 1)));
	if(create_key_AES(key_bytes, 128, &aes_key)) {
		printf("ERROR");
		return;
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
	if(create_key_AES(key_bytes, 192, &aes_key)) {
		printf("ERROR");
		return;
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

void size256Test() {
	unsigned char key_bytes[32] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
	AES_KEY aes_key;
	memset(&aes_key, 0, (16 * (MAX_RNDS + 1)));
	if(create_key_AES(key_bytes, 256, &aes_key)) {
		printf("ERROR");
		return;
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

void mix_columns_test() {
	unsigned char a[4] = {0xdb, 0x13, 0x53, 0x45};
	mix_single_column(a);
	printf("%x %x %x %x\n", a[0], a[1], a[2], a[3]);
}

void aes_test() {
	unsigned char in[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	unsigned char key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	unsigned char out[16];
	unsigned char ori[16];
	AES_KEY aes_key;
	memset(&aes_key, 0, (16 * (MAX_RNDS + 1)));
	create_key_AES(key, 128, &aes_key);
	printbuf(key, 16);
	printbuf(in, 16);
	encrypt_block_AES(in, out, &aes_key);
	printbuf(out, 16);
	decrypt_block_AES(out, ori, &aes_key);
	printbuf(ori, 16);
}

int main() {
	aes_test();
}
