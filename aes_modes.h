#ifndef IBUR_AES_MODES_H
#define IBUR_AES_MODES_H

#include <stdint.h>

#include "aes.h"

int encrypt_cbc_AES(const uint8_t* const message, const uint32_t length, const uint8_t* const iv, const AES_KEY* const key, uint8_t* const out);

int decrypt_cbc_AES(const uint8_t* const message, const uint32_t length, const uint8_t* const iv, const AES_KEY* const key, uint8_t* const out);

int encrypt_ctr_AES(const uint8_t* const message, const uint32_t length, const uint8_t* const nonce, const AES_KEY* const key, uint8_t* const out);

int decrypt_ctr_AES(const uint8_t* const message, const uint32_t length, const uint8_t* const nonce, const AES_KEY* const key, uint8_t* const out);

#endif
