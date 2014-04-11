#include <stdio.h>

#include "pkcs7pad.h"
#include "test.h"
#include "util.h"

int main() {
	{
		unsigned char out[16];
		pkcs7pad(from_hex("00"), 1, 16, out);
		assert_equals(out, from_hex("000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"), 16, "Pad of 00 was not valid");
	}
	{
		unsigned char out[16];
		pkcs7pad(from_hex("00 ff ff ff ff ff ff ff ff ff fe"), 11, 16, out);
		assert_equals(out, from_hex("00 ff ff ff ff ff ff ff ff ff fe 05 05 05 05 05"), 16, "Pad of 00 ff ff ff ff ff ff ff ff ff fe was not valid");
	}
	{
		unsigned char out[16];
		pkcs7pad(from_hex("00 ff ff ff ff ff ff ff ff ff fe 05 05 05 05 05"), 16, 16, out);
		assert_equals(out, 
			from_hex("00 ff ff ff ff ff ff ff ff ff fe 05 05 05 05 05 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10"), 
			16, "Pad of 00 ff ff ff ff ff ff ff ff ff fe 05 05 05 05 05 was not valid");
	}
}
