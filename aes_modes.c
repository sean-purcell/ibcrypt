#include <errno.h>
#include <string.h>

#include <libibur/util.h>

#include "aes.h"

/* initialize an aes ctr context.  recommended for large messages instead of putting it all in one buffer */
AES_CBC_CTX* init_cbc_AES(const AES_KEY* const key, const uint8_t iv[16]) {
	AES_CBC_CTX* ctx;
	
	if((ctx = malloc(sizeof(AES_CBC_CTX))) == NULL) {
		errno = ENOMEM;
		goto err0;
	}
	
	memcpy(&ctx->key, key, sizeof(AES_KEY));
	memcpy(&ctx->prev[0], iv, 16);
	
	ctx->count = 0;
	
	/* success! */
	return ctx;
	
err0:
	/* failure! */
	return NULL;
}

/* returns the size of the output buffer required for an update of size blen */
uint32_t output_size(const AES_CBC_CTX* const ctx, const uint32_t blen) {
	uint32_t mod = ctx->count % 16;
	return ((blen + mod) / 16) * 16;
}

#define min(a, b) ((a) > (b) ? (a) : (b))

/* returns the amount written to the buffer */
uint32_t enc_cbc_AES(AES_CBC_CTX* const ctx, const uint8_t* in, uint32_t len, uint8_t* out) {
	uint32_t written = 0;
	uint32_t mod;
	while(len > 0) {
		mod = ctx->count % 16;
		if(mod != 0) {
			uint32_t wrlen = min(16-mod, len);
			memcpy(&ctx->buf[mod], in, wrlen);
			len -= wrlen;
			in += wrlen;
			ctx->count += wrlen;
		} else {
			uint32_t wrlen = min(16, len);
			memcpy(ctx->buf, in, wrlen);
			len -= wrlen;
			in += wrlen;
			ctx->count += wrlen;
		}
		if(ctx->count % 16 == 0) {
			encrypt_block_AES(ctx->buf, out, &ctx->key);
			out += 16;
			written += 16;
		}
	}
	
	return written;
}

int encrypt_buf_cbc_AES(const uint8_t* const message, const uint32_t length, const uint8_t* const iv, const AES_KEY* const key, uint8_t* const out) {
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

int decrypt_buf_cbc_AES(const uint8_t* const message, const uint32_t length, const uint8_t* const iv, const AES_KEY* const key, uint8_t* const out) {
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

/* initialize an aes ctr context.  recommended for large messages instead of putting it all in one buffer */
AES_CTR_CTX* init_ctr_AES(const AES_KEY* const key, const uint8_t* const nonce, const uint32_t noncelen) {
	if(noncelen == 0 || noncelen > 16) {
		/* not ok */
		goto err0;
	}
	
	AES_CTR_CTX* ctx;
	
	if((ctx = malloc(sizeof(AES_CTR_CTX))) == NULL) {
		errno = ENOMEM;
		goto err0;
	}
	
	memcpy(&ctx->key, key, sizeof(AES_KEY));
	memcpy(&ctx->nonce[0], nonce, noncelen);
	memset(&ctx->nonce[noncelen], 0x00, 16 - noncelen);
	
	ctx->count = 0;
	
	/* success! */
	return ctx;
	
err0:
	/* failure! */
	return NULL;
}

/* encrypt/decrypt a block of ctr */
void stream_ctr_AES(AES_CTR_CTX* const ctx, const uint8_t* const in, const size_t len, uint8_t* const out) {
	uint32_t i;
	
	for(i = 0; i < len; i++) {
		if(ctx->count % 16 == 0) {
			encrypt_block_AES(ctx->nonce, ctx->stream, &ctx->key);
			add_one(ctx->nonce);
		}
		out[i] = in[i] ^ ctx->stream[ctx->count%16];
		ctx->count++;
	}
}

/* free the context and zero the memory */
void free_ctr_AES(AES_CTR_CTX* ctx) {
	memset(ctx, 0, sizeof(AES_CTR_CTX));
	free(ctx);
}

int encrypt_ctr_AES(const uint8_t* const message, const uint32_t length, const uint8_t nonce[16], const AES_KEY* const key, uint8_t* const out) {
	AES_CTR_CTX* ctx = init_ctr_AES(key, nonce, 16);
	if(ctx == NULL) {
		/* failure */
		return -1;
	}
	
	stream_ctr_AES(ctx, message, length, out);
	free_ctr_AES(ctx);
	return 0;
}

int decrypt_ctr_AES(const uint8_t* const message, const uint32_t length, const uint8_t nonce[16], const AES_KEY* const key, uint8_t* const out) {
	return encrypt_ctr_AES(message, length, nonce, key, out);
}
