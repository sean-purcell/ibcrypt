#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void printbuf(const unsigned char* const buf, const int size) {
	for(int i = 0; i < size; i++) {
		if(buf[i] < 16) {
			printf("0");
		}
		printf("%x ", buf[i]);
	}
	printf("\n");
}

/**
 * NOTE: Buffers obtained from this MUST be freed
 */
unsigned char* from_hex(const char* const hex) {
	int len = 0;
	int i = 0;
	while(hex[i]) {
		char c = hex[i];
		if((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			len++;
		}
		i++;
	}
	
	if(len % 2 == 1) {
		return NULL;
	}
	
	unsigned char* buf = (unsigned char*) malloc(len / 2 * sizeof(unsigned char));
	memset(buf, 0, len / 2 * sizeof(unsigned char));
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
	return buf;
}

void xor_bytes(const uint8_t* const a, const uint8_t* const b, const uint32_t len, uint8_t* const o) {
	for(uint32_t i = 0; i < len; i++) {
		o[i] = a[i] ^ b[i];
	}
}
