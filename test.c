/**
 * A set of functions to facilitate testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "util.h"

void assert_equals(const uint8_t* const a, const uint8_t* const b, int len, const char* const message) {
	for(int i = 0; i < len; i++) {
		if(a[i] != b[i]) {
			printf("%s failed\n", message);
			printbuf(a, len);
			printbuf(b, len);
			exit(-1);
		}
	}
	printf("%s passed\n", message);
}
