#ifndef IBCRYPT_UTIL_H
#define IBCRYPT_UTIL_H

#include <stdint.h>

void printbuf(const void* const buf, const int size);

void from_hex(const char* const hex, uint8_t* const buf);

void xor_bytes(const void* const a, const void* const b, const uint32_t len, void* const o);

#endif
