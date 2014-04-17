#include <string.h>

#include "aes.h"
#include "util.h"

int encrypt_cbc_AES(const uint8_t* const message, const uint32_t length, const uint8_t* const iv, const AES_KEY* const key, uint8_t* const out) {
	if(length % 16 != 0) {
		return -1; // must be of proper size
	}
	
	uint8_t prev[16];
	memcpy(prev, iv, 16); // set up init vector
	
	uint8_t encbuf[16];
	
	for(uint32_t i = 0; i < length / 16; i++) {
		xor_bytes(message + i * 16, prev, 16, encbuf); // xor in iv
		encrypt_block_AES(encbuf, prev, key); // encrypt block
		memcpy(out + i * 16, prev, 16); // copy to output
	}
	return 0;
}

int decrypt_cbc_AES(const uint8_t* const message, const uint32_t length, const uint8_t* const iv, const AES_KEY* const key, uint8_t* const out) {
	if(length % 16 != 0) {
		return -1; // must be of proper size
	}
	
	uint8_t prev[16];
	memcpy(prev, iv, 16); // set up init vector
	
	uint8_t decbuf[16];
	
	for(uint32_t i = 0; i < length / 16; i++) {
		decrypt_block_AES(message + i * 16, decbuf, key); // decrypt block
		xor_bytes(decbuf, prev, 16, out + i * 16); // write to output
		memcpy(prev, message + i * 16, 16); // copy ciphertext for next prev
	}
	
	return 0;
}

// adds 1, iterating through to carry if necessary
static void add_one(uint8_t* const nonce) {
	for(int i = 15; i >= 0; i--) {
		nonce[i]++;
		if(nonce[i] != 0) {
			return;
		}
	}
}

int encrypt_ctr_AES(const uint8_t* const message, const uint32_t length, const uint8_t* const nonce, const AES_KEY* const key, uint8_t* const out) {
	uint8_t encrypt_block[16];
	// copy nonce into encrypt_block
	memcpy(encrypt_block, nonce, 16);
	
	uint8_t keystream[16];
	
	for(int i = 0; i < length; i++) {
		
		uint8_t mod = i % 16;
		if(mod == 0) { // generate more keystream bytes
			encrypt_block_AES(encrypt_block, keystream, key);
			add_one(encrypt_block);
		}
		
		out[i] = message[i] ^ keystream[mod];
	}
	
	return 0;
}

int decrypt_ctr_AES(const uint8_t* const message, const uint32_t length, const uint8_t* const nonce, const AES_KEY* const key, uint8_t* const out) {
	return encrypt_ctr_AES(message, length, nonce, key, out);
}
