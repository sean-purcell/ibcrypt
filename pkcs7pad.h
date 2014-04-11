#ifndef IBUR_PKCS7PAD_H
#define IBUR_PKCS7PAD_H

/**
 * out must be a buffer of size at least (len/BK_SIZE + 1) * BK_SIZE
 */
void pkcs7pad(const unsigned char* const message, const int len, const int BK_SIZE, unsigned char* const out);
	
void pkcs7pad(const unsigned char* const padded_message, const int len, const int BK_SIZE, unsigned char* const out);
	
#endif