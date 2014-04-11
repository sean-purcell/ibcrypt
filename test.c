/**
 * A set of functions to facilitate testing
 */

#include <stdio.h>
#include <stdlib.h>

#include "util.h"

void assert_equals(const unsigned char* const a, const unsigned char* const b, int len, const char* const errString) {
	for(int i = 0; i < len; i++) {
		if(a[i] != b[i]) {
			printf(errString);
			printf("\n");
			exit(-1);
		}
	}
}
