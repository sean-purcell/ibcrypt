#include "scrypt.c"
#include <stdio.h>

void salsa20_8coretest() {
	char* bytes = "7e879a21 4f3ec986 7ca940e6 41718f26\
   baee555b 8c61c1b5 0df84611 6dcd3b1d\
   ee24f319 df9b3d85 14121e4b 5ac5aa32\
   76021d29 09c74829 edebc68d b8b8c25e";
	uint8_t vals[64];
	from_hex(bytes, vals);
	salsa20_8(vals);
	printbuf(vals, 64);
}

void block_mix_test() {
	char* in = "f7ce0b65 3d2d72a4 108cf5ab e912ffdd\
	           777616db bb27a70e 8204f3ae 2d0f6fad\
	           89f68f48 11d1e87b cc3bd740 0a9ffd29\
	           094f0184 639574f3 9ae5a131 5217bcd7\
	           89499144 7213bb22 6c25b54d a86370fb\
	           cd984380 374666bb 8ffcb5bf 40c254b0\
	           67d27c51 ce4ad5fe d829c90b 505a571b\
	           7f4d1cad 6a523cda 770e67bc eaaf7e89";
			   
	uint8_t vals[128];
	from_hex(in, vals);
	blockmix(vals, 1, vals);
	printbuf(vals, 128);
}

void scrypt_romix() {
	char* in = "f7ce0b65 3d2d72a4 108cf5ab e912ffdd\
       777616db bb27a70e 8204f3ae 2d0f6fad\
       89f68f48 11d1e87b cc3bd740 0a9ffd29\
       094f0184 639574f3 9ae5a131 5217bcd7\
       89499144 7213bb22 6c25b54d a86370fb\
       cd984380 374666bb 8ffcb5bf 40c254b0\
       67d27c51 ce4ad5fe d829c90b 505a571b\
       7f4d1cad 6a523cda 770e67bc eaaf7e89";
	
	uint8_t vals[128];
	from_hex(in, vals);
	smix(vals, 16, 1);
	printbuf(vals, 128);
}

int main() {
	//salsa20_8coretest();
	//block_mix_test();
	//scrypt_romix();
	uint8_t test[64];
	char* out = "77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97\
f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42\
fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17\
e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06";
	
	char* pass = "password";
	char* salt = "NaCl";
	
	from_hex(out, test);
	
	uint8_t res[64];
	
	if(scrypt(pass, 8, salt, 4, 1024, 8, 16, 64, res)) {
		printf("Error: %u\n", errno);
	}
	printbuf(res, 64);
}
