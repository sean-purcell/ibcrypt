#ifndef IBUR_UTIL_H
#define IBUR_UTIL_H

#include <stdint.h>

void printbuf(const uint8_t* const buf, const int size);

void from_hex(const char* const hex, uint8_t* const buf);

void xor_bytes(const uint8_t* const a, const uint8_t* const b, const uint32_t len, uint8_t* const o);

#endif
