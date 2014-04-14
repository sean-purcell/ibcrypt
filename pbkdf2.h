#ifndef IBUR_PBKDF2_H
#define IBUR_PBKDF2_H

#include "stdint.h"

void pbkdf2(void (*prf)(const uint8_t* const key, const uint32_t keylen, const uint8_t* const message, uint32_t len, uint8_t* const out),
	const uint32_t hlen, const uint8_t* const pass, const uint32_t plen, const uint8_t* salt, const uint32_t saltLen, const uint32_t c, const uint32_t dkLen, uint8_t* const out);

#endif