#include <string.h>
#include <stdint.h>

int pkcs7pad(const uint8_t* const message, const int len, const int BK_SIZE, uint8_t* const out) {
	const int nsize = (len / BK_SIZE + 1) * BK_SIZE;
	memset(out, 0, nsize);
	memcpy(out, message, len);
	const int pad = nsize - len;
	for(int i = len; i < nsize; i++) {
		out[i] = pad;
	}
	return 0;
}

int pkcs7unpad(const uint8_t* const padded_message, const int len, const int BK_SIZE, uint8_t* const out) {
	if(len % BK_SIZE != 0) {
		return -1;
	}
	
	const int pad = padded_message[len-1];
	memcpy(out, padded_message, len-pad);
	return 0;
}
