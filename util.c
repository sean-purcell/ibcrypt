#ifndef IBUR_CRYPTO_UTIL
#define IBUR_CRYPTO_UTIL


void printbuf(const unsigned char* const buf, const int size) {
	for(int i = 0; i < size; i++) {
		if(buf[i] < 16) {
			printf("0");
		}
		printf("%x ", buf[i]);
	}
	printf("\n");
}


#endif
