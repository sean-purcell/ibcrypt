#include <string.h>

int pkcs7pad(const unsigned char* const message, const int len, const int BK_SIZE, unsigned char* const out) {
	const int nsize = (len / BK_SIZE + 1) * BK_SIZE;
	memset(out, 0, nsize);
	memcpy(out, message, len);
	const int pad = nsize - len;
	for(int i = len; i < nsize; i++) {
		out[i] = pad;
	}
	return 0;
}

int pkcs7unpad(const unsigned char* const padded_message, const int len, const int BK_SIZE, unsigned char* const out) {
	if(len % BK_SIZE != 0) {
		return -1;
	}
	
	const int pad = padded_message[len-1];
	memcpy(out, padded_message, len-pad);
	return 0;
}
