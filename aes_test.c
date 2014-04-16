/**
 * NIST AESAVS Test vectors for AES
 */

#include <string.h>

#include "aes.h"
#include "util.h"
#include "test.h"

#define A_SIZE(x) (sizeof(x)/sizeof(x[0]))

// plaintext:ciphertext
const char* GFSBox128[] = {
	"f34481ec3cc627bacd5dc3fb08f273e6", "0336763e966d92595a567cc9ce537f5e",
	"9798c4640bad75c7c3227db910174e72", "a9a1631bf4996954ebc093957b234589", 
	"96ab5c2ff612d9dfaae8c31f30c42168", "ff4f8391a6a40ca5b25d23bedd44a597",
	"6a118a874519e64e9963798a503f1d35", "dc43be40be0e53712f7e2bf5ca707209",
	"cb9fceec81286ca3e989bd979b0cb284", "92beedab1895a94faa69b632e5cc47ce",
	"b26aeb1874e47ca8358ff22378f09144", "459264f4798f6a78bacb89c15ed3d601",
	"58c8e00b2631686d54eab84b91f0aca1", "08a4e2efec8a8e3312ca7460b9040bbf" 
};	

void GFSBox128Test() {
	uint8_t key_bytes[16];
	from_hex("00000000000000000000000000000000", key_bytes);
	
	AES_KEY key;
	create_key_AES(key_bytes, 128, &key);
	
	for(int i = 0; i < A_SIZE(GFSBox128) / 2; i++) {
		uint8_t ptext[16];
		uint8_t ctext[16];
		uint8_t outc[16];
		uint8_t outp[16];
		
		from_hex(GFSBox128[i*2+0], ptext);
		from_hex(GFSBox128[i*2+1], ctext);
		
		encrypt_block_AES(ptext, outc, &key);
		decrypt_block_AES(outc, outp, &key);
		assert_equals(outc, ctext, 16, "AES GFSBox128 enc test");
		assert_equals(outp, ptext, 16, "AES GFSBox128 dec test");
	}
}

// plaintext:ciphertext
const char* GFSBox192[] = {
	"1b077a6af4b7f98229de786d7516b639", "275cfc0413d8ccb70513c3859b1d0f72",
	"9c2d8842e5f48f57648205d39a239af1", "c9b8135ff1b5adc413dfd053b21bd96d",
	"bff52510095f518ecca60af4205444bb", "4a3650c3371ce2eb35e389a171427440",
	"51719783d3185a535bd75adc65071ce1", "4f354592ff7c8847d2d0870ca9481b7c",
	"26aa49dcfe7629a8901a69a9914e6dfd", "d5e08bf9a182e857cf40b3a36ee248cc",
	"941a4773058224e1ef66d10e0a6ee782", "067cd9d3749207791841562507fa9626"
};	

void GFSBox192Test() {
	uint8_t key_bytes[24];
	from_hex("000000000000000000000000000000000000000000000000", key_bytes);
	
	AES_KEY key;
	create_key_AES(key_bytes, 192, &key);
	
	for(int i = 0; i < A_SIZE(GFSBox192) / 2; i++) {
		uint8_t ptext[16];
		uint8_t ctext[16];
		uint8_t outc[16];
		uint8_t outp[16];
		
		from_hex(GFSBox192[i*2+0], ptext);
		from_hex(GFSBox192[i*2+1], ctext);
		
		encrypt_block_AES(ptext, outc, &key);
		decrypt_block_AES(outc, outp, &key);
		assert_equals(outc, ctext, 16, "AES GFSBox192 enc test");
		assert_equals(outp, ptext, 16, "AES GFSBox192 dec test");
	}
}

// plaintext:ciphertext
const char* GFSBox256[] = {
	"014730f80ac625fe84f026c60bfd547d", "5c9d844ed46f9885085e5d6a4f94c7d7",
	"0b24af36193ce4665f2825d7b4749c98", "a9ff75bd7cf6613d3731c77c3b6d0c04",
	"761c1fe41a18acf20d241650611d90f1", "623a52fcea5d443e48d9181ab32c7421",
	"8a560769d605868ad80d819bdba03771", "38f2c7ae10612415d27ca190d27da8b4",
	"91fbef2d15a97816060bee1feaa49afe", "1bc704f1bce135ceb810341b216d7abe"
};	

void GFSBox256Test() {
	uint8_t key_bytes[32];
	from_hex("0000000000000000000000000000000000000000000000000000000000000000", key_bytes);
	
	AES_KEY key;
	create_key_AES(key_bytes, 256, &key);
	
	for(int i = 0; i < A_SIZE(GFSBox256) / 2; i++) {
		uint8_t ptext[16];
		uint8_t ctext[16];
		uint8_t outc[16];
		uint8_t outp[16];
		
		from_hex(GFSBox256[i*2+0], ptext);
		from_hex(GFSBox256[i*2+1], ctext);
		
		encrypt_block_AES(ptext, outc, &key);
		decrypt_block_AES(outc, outp, &key);
		assert_equals(outc, ctext, 16, "AES GFSBox256 enc test");
		assert_equals(outp, ptext, 16, "AES GFSBox256 dec test");
	}
}

// key:ciphertext
const char* KeySbox128[] = {
	"10a58869d74be5a374cf867cfb473859", "6d251e6944b051e04eaa6fb4dbf78465",
	"caea65cdbb75e9169ecd22ebe6e54675", "6e29201190152df4ee058139def610bb",
	"a2e2fa9baf7d20822ca9f0542f764a41", "c3b44b95d9d2f25670eee9a0de099fa3",
	"b6364ac4e1de1e285eaf144a2415f7a0", "5d9b05578fc944b3cf1ccf0e746cd581",
	"64cf9c7abc50b888af65f49d521944b2", "f7efc89d5dba578104016ce5ad659c05",
	"47d6742eefcc0465dc96355e851b64d9", "0306194f666d183624aa230a8b264ae7",
	"3eb39790678c56bee34bbcdeccf6cdb5", "858075d536d79ccee571f7d7204b1f67",
	"64110a924f0743d500ccadae72c13427", "35870c6a57e9e92314bcb8087cde72ce",
	"18d8126516f8a12ab1a36d9f04d68e51", "6c68e9be5ec41e22c825b7c7affb4363",
	"f530357968578480b398a3c251cd1093", "f5df39990fc688f1b07224cc03e86cea",
	"da84367f325d42d601b4326964802e8e", "bba071bcb470f8f6586e5d3add18bc66",
	"e37b1c6aa2846f6fdb413f238b089f23", "43c9f7e62f5d288bb27aa40ef8fe1ea8",
	"6c002b682483e0cabcc731c253be5674", "3580d19cff44f1014a7c966a69059de5",
	"143ae8ed6555aba96110ab58893a8ae1", "806da864dd29d48deafbe764f8202aef",
	"b69418a85332240dc82492353956ae0c", "a303d940ded8f0baff6f75414cac5243",
	"71b5c08a1993e1362e4d0ce9b22b78d5", "c2dabd117f8a3ecabfbb11d12194d9d0",
	"e234cdca2606b81f29408d5f6da21206", "fff60a4740086b3b9c56195b98d91a7b",
	"13237c49074a3da078dc1d828bb78c6f", "8146a08e2357f0caa30ca8c94d1a0544",
	"3071a2a48fe6cbd04f1a129098e308f8", "4b98e06d356deb07ebb824e5713f7be3",
	"90f42ec0f68385f2ffc5dfc03a654dce", "7a20a53d460fc9ce0423a7a0764c6cf2",
	"febd9a24d8b65c1c787d50a4ed3619a9", "f4a70d8af877f9b02b4c40df57d45b17"
};

void KeySbox128Test() {
	uint8_t ptext[16];
	from_hex("00000000000000000000000000000000", ptext);
	
	for(int i = 0; i < A_SIZE(KeySbox128) / 2; i++) {
		uint8_t key_b[16];
		uint8_t ctext[16];
		uint8_t outc[16];
		uint8_t outp[16];
		
		from_hex(KeySbox128[i*2+0], key_b);
		from_hex(KeySbox128[i*2+1], ctext);
		
		AES_KEY key;
		create_key_AES(key_b, 128, &key);
		
		encrypt_block_AES(ptext, outc, &key);
		decrypt_block_AES(outc, outp, &key);
		assert_equals(outc, ctext, 16, "AES KeySbox128 enc test");
		assert_equals(outp, ptext, 16, "AES KeySbox128 dec test");
	}
}

// key:ciphertext
const char* KeySbox192[] = {
	"e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd", "0956259c9cd5cfd0181cca53380cde06",
	"15d20f6ebc7e649fd95b76b107e6daba967c8a9484797f29", "8e4e18424e591a3d5b6f0876f16f8594",
	"a8a282ee31c03fae4f8e9b8930d5473c2ed695a347e88b7c", "93f3270cfc877ef17e106ce938979cb0",
	"cd62376d5ebb414917f0c78f05266433dc9192a1ec943300", "7f6c25ff41858561bb62f36492e93c29",
	"502a6ab36984af268bf423c7f509205207fc1552af4a91e5", "8e06556dcbb00b809a025047cff2a940",
	"25a39dbfd8034f71a81f9ceb55026e4037f8f6aa30ab44ce", "3608c344868e94555d23a120f8a5502d",
	"e08c15411774ec4a908b64eadc6ac4199c7cd453f3aaef53", "77da2021935b840b7f5dcc39132da9e5",
	"3b375a1ff7e8d44409696e6326ec9dec86138e2ae010b980", "3b7c24f825e3bf9873c9f14d39a0e6f4",
	"950bb9f22cc35be6fe79f52c320af93dec5bc9c0c2f9cd53", "64ebf95686b353508c90ecd8b6134316",
	"7001c487cc3e572cfc92f4d0e697d982e8856fdcc957da40", "ff558c5d27210b7929b73fc708eb4cf1"
};

void KeySbox192Test() {
	uint8_t ptext[16];
	from_hex("00000000000000000000000000000000", ptext);
	
	for(int i = 0; i < A_SIZE(KeySbox192) / 2; i++) {
		uint8_t key_b[24];
		uint8_t ctext[16];
		uint8_t outc[16];
		uint8_t outp[16];
		
		from_hex(KeySbox192[i*2+0], key_b);
		from_hex(KeySbox192[i*2+1], ctext);
		
		AES_KEY key;
		create_key_AES(key_b, 192, &key);
		
		encrypt_block_AES(ptext, outc, &key);
		decrypt_block_AES(outc, outp, &key);
		assert_equals(outc, ctext, 16, "AES KeySbox192 enc test");
		assert_equals(outp, ptext, 16, "AES KeySbox192 dec test");
	}
}

void aes_tests() {
	GFSBox128Test();
	GFSBox192Test();
	GFSBox256Test();
	KeySbox128Test();
	KeySbox192Test();
}