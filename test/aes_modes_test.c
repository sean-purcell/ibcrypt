#include <stdint.h>
#include <stdlib.h>

#include <libibur/test.h>
#include <libibur/util.h>

#include "aes.h"

const char* keys_ctr[] = {
	"2b7e151628aed2a6abf7158809cf4f3c",
	"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
	"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
};

const uint16_t key_size_ctr[] = {
	128,
	192,
	256
};

const char* nonces_ctr[] = {
	"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
	"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
	"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
};

const char* ptexts_ctr[] = {
	"6bc1bee22e409f96e93d7e117393172a\
	 ae2d8a571e03ac9c9eb76fac45af8e51\
	 30c81c46a35ce411e5fbc1191a0a52ef\
	 f69f2445df4f9b17ad2b417be66c3710",
	"6bc1bee22e409f96e93d7e117393172a\
	 ae2d8a571e03ac9c9eb76fac45af8e51\
	 30c81c46a35ce411e5fbc1191a0a52ef\
	 f69f2445df4f9b17ad2b417be66c3710",
	"6bc1bee22e409f96e93d7e117393172a\
	 ae2d8a571e03ac9c9eb76fac45af8e51\
	 30c81c46a35ce411e5fbc1191a0a52ef\
	 f69f2445df4f9b17ad2b417be66c3710"
};

const char* ctexts_ctr[] = {
	"874d6191b620e3261bef6864990db6ce\
	 9806f66b7970fdff8617187bb9fffdff\
	 5ae4df3edbd5d35e5b4f09020db03eab\
	 1e031dda2fbe03d1792170a0f3009cee",
	"1abc932417521ca24f2b0459fe7e6e0b\
	 090339ec0aa6faefd5ccc2c6f4ce8e94\
	 1e36b26bd1ebc670d1bd1d665620abf7\
	 4f78a7f6d29809585a97daec58c6b050",
	"601ec313775789a5b7a7f504bbf3d228\
	 f443e3ca4d62b59aca84e990cacaf5c5\
	 2b0930daa23de94ce87017ba2d84988d\
	 dfc9c58db67aada613c2dd08457941a6"
	
};

const uint32_t len_ctr[] = {
	64,
	64,
	64
};

void AES_CTR_Test() {
	for(int i = 0; i < sizeof(len_ctr)/sizeof(len_ctr[0]); i++) {
		uint8_t* key_bytes = (uint8_t*) malloc(key_size_ctr[i] / 8);
		uint8_t* nonce = (uint8_t*) malloc(16);
		uint8_t* ptext = (uint8_t*) malloc(len_ctr[i]);
		uint8_t* ctext = (uint8_t*) malloc(len_ctr[i]);
		
		uint8_t* outc = (uint8_t*) malloc(len_ctr[i]);
		uint8_t* outp = (uint8_t*) malloc(len_ctr[i]);
		
		from_hex(keys_ctr[i], key_bytes);
		from_hex(nonces_ctr[i], nonce);
		from_hex(ptexts_ctr[i], ptext);
		from_hex(ctexts_ctr[i], ctext);
		
		AES_KEY k;
		create_key_AES(key_bytes, key_size_ctr[i], &k);
		
		encrypt_ctr_AES(ptext, len_ctr[i], nonce, &k, outc);
		decrypt_ctr_AES(ctext, len_ctr[i], nonce, &k, outp);
		
		assert_equals(ctext, outc, len_ctr[i], "AES CTR test");
		assert_equals(ptext, outp, len_ctr[i], "AES CTR test");
		
		free(key_bytes);
		free(nonce);
		free(ptext);
		free(ctext);
	}
}

const char* keys_cbc[] = {
	"2b7e151628aed2a6abf7158809cf4f3c",
	"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
	"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
};

const uint16_t key_size_cbc[] = {
	128,
	192,
	256
};

const char* ivs_cbc[] = {
	"000102030405060708090a0b0c0d0e0f",
	"000102030405060708090a0b0c0d0e0f",
	"000102030405060708090a0b0c0d0e0f"
};

const char* ptexts_cbc[] = {
	"6bc1bee22e409f96e93d7e117393172a\
	 ae2d8a571e03ac9c9eb76fac45af8e51\
	 30c81c46a35ce411e5fbc1191a0a52ef\
	 f69f2445df4f9b17ad2b417be66c3710",
	"6bc1bee22e409f96e93d7e117393172a\
	 ae2d8a571e03ac9c9eb76fac45af8e51\
	 30c81c46a35ce411e5fbc1191a0a52ef\
	 f69f2445df4f9b17ad2b417be66c3710",
	"6bc1bee22e409f96e93d7e117393172a\
	 ae2d8a571e03ac9c9eb76fac45af8e51\
	 30c81c46a35ce411e5fbc1191a0a52ef\
	 f69f2445df4f9b17ad2b417be66c3710"
};

const char* ctexts_cbc[] = {
	"7649abac8119b246cee98e9b12e9197d\
	 5086cb9b507219ee95db113a917678b2\
	 73bed6b8e3c1743b7116e69e22229516\
	 3ff1caa1681fac09120eca307586e1a7",
	"4f021db243bc633d7178183a9fa071e8\
	 b4d9ada9ad7dedf4e5e738763f69145a\
	 571b242012fb7ae07fa9baac3df102e0\
	 08b0e27988598881d920a9e64f5615cd",
	"f58c4c04d6e5f1ba779eabfb5f7bfbd6 \
	 9cfc4e967edb808d679f777bc6702c7d\
	 39f23369a9d9bacfa530e26304231461\
	 b2eb05e2c39be9fcda6c19078c6a9d1b"
	
};

const uint32_t len_cbc[] = {
	64,
	64,
	64
};

void AES_CBC_Test() {
	for(int i = 0; i < sizeof(len_cbc)/sizeof(len_cbc[0]); i++) {
		uint8_t* key_bytes = (uint8_t*) malloc(key_size_cbc[i] / 8);
		uint8_t* iv = (uint8_t*) malloc(16);
		uint8_t* ptext = (uint8_t*) malloc(len_cbc[i]);
		uint8_t* ctext = (uint8_t*) malloc(len_cbc[i]);
		
		uint8_t* outc = (uint8_t*) malloc(len_cbc[i]);
		uint8_t* outp = (uint8_t*) malloc(len_cbc[i]);
		
		from_hex(keys_cbc[i], key_bytes);
		from_hex(ivs_cbc[i], iv);
		from_hex(ptexts_cbc[i], ptext);
		from_hex(ctexts_cbc[i], ctext);
		
		AES_KEY k;
		create_key_AES(key_bytes, key_size_cbc[i], &k);
		
		encrypt_cbc_AES(ptext, len_cbc[i], iv, &k, outc);
		decrypt_cbc_AES(ctext, len_cbc[i], iv, &k, outp);
		
		assert_equals(ctext, outc, len_cbc[i], "AES CBC test");
		assert_equals(ptext, outp, len_cbc[i], "AES CBC test");
		
		free(key_bytes);
		free(iv);
		free(ptext);
		free(ctext);
	}
}

void aes_mode_tests() {
	AES_CTR_Test();
	AES_CBC_Test();
}
