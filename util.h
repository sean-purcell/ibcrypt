#ifndef IBUR_UTIL_H
#define IBUR_UTIL_H

void printbuf(const unsigned char* const buf, const int size);

/**
 * NOTE: Buffers obtained from this MUST be freed
 */
unsigned char* from_hex(const char* const hex);

#endif
