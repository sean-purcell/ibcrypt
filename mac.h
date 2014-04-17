#ifndef IBCRYPT_MAC_H
#define IBCRYPT_MAC_H

/* implemented in sha256.c */
void hmac_sha256(const uint8_t* const key, const uint32_t keylen, const uint8_t* const message, uint32_t len, uint8_t* const out);

void cmac_aes(const uint8_t* const key, const uint32_t keylen, const uint8_t* const message,)

#endif
