#ifndef IBUR_PKCS7PAD_H
#define IBUR_PKCS7PAD_H

#include <stdint.h>

/**
 * out must be a buffer of size at least (len/BK_SIZE + 1) * BK_SIZE
 */
void pkcs7pad(const uint8_t* const message, const int len, const int BK_SIZE, uint8_t* const out);
	
void pkcs7pad(const uint8_t* const padded_message, const int len, const int BK_SIZE, uint8_t* const out);
	
#endif