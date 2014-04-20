#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void printbuf(const void* const _buf, const int size) {
	const uint8_t* const buf = (uint8_t*) _buf;
	for(int i = 0; i < size; i++) {
		if(buf[i] < 16) {
			printf("0");
		}
		printf("%x ", buf[i]);
	}
	printf("\n");
}

void from_hex(const char* const hex, uint8_t* const buf) {
	int len = 0;
	int i = 0;
	while(hex[i]) {
		char c = hex[i];
		if((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			len++;
		}
		i++;
	}
	// add 1 to len in case an extra nibble is needed
	memset(buf, 0, (len + 1) / 2 * sizeof(unsigned char));
	i = 0;
	int bufi = 0;
	while(hex[i]) {
		char c = hex[i];
		if(c >= '0' && c <= '9') {
			buf[bufi/2] |= (c - '0') << (bufi % 2 == 0 ? 4 : 0);
			bufi++;
		} else if((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			c |= 0x20; // convert to lower case by flipping bit 5
			           // (e.g. 'A':0100 0001->'a':0110 0001)
			buf[bufi/2] |= (c - 'a' + 10) << (bufi % 2 == 0 ? 4 : 0);
			bufi++;
		}
		i++;
	}
}

void xor_bytes(const void* const _a, const void* const _b, const uint32_t len, void* const _o) {
	const uint8_t* const a = (uint8_t*) _a;
	const uint8_t* const b = (uint8_t*) _b;
	uint8_t* const o = (uint8_t*) _o;
	for(uint32_t i = 0; i < len; i++) {
		o[i] = a[i] ^ b[i];
	}
}
