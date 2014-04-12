#ifndef IBUR_SHA256_H
#define IBUR_SHA256_H

#include <stdint.h>

#define SHA_256_DEBUG 0

void hash_sha256(const uint8_t* const message, const unsigned long size, uint8_t* const out);

#endif
