#include <libibur/test.h>

#include "salsa20.h"

void salsa20_core_tests() {
	{
		uint8_t b[64] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		uint8_t o[64] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		salsa20_core(b,b);
		assert_equals(b, o, 64, "SALSA20 CORE");
	}
	{
		uint8_t b[64] = {211,159, 13,115, 76, 55, 82,183, 3,117,222, 37,191,187,234,136,
			49,237,179, 48, 1,106,178,219,175,199,166, 48, 86, 16,179,207,
			31,240, 32, 63, 15, 83, 93,161,116,147, 48,113,238, 55,204, 36,
			79,201,235, 79, 3, 81,156, 47,203, 26,244,243, 88,118,104, 54};
		uint8_t o[64] = {109, 42,178,168,156,240,248,238,168,196,190,203, 26,110,170,154,
			29, 29,150, 26,150, 30,235,249,190,163,251, 48, 69,144, 51, 57,
			118, 40,152,157,180, 57, 27, 94,107, 42,236, 35, 27,111,114,114,
			219,236,232,135,111,155,110, 18, 24,232, 95,158,179, 19, 48,202};
		salsa20_core(b,b);
		assert_equals(b, o, 64, "SALSA20 CORE");
	}
	{
		uint8_t b[64] = {88,118,104, 54, 79,201,235, 79, 3, 81,156, 47,203, 26,244,243,
			191,187,234,136,211,159, 13,115, 76, 55, 82,183, 3,117,222, 37,
			86, 16,179,207, 49,237,179, 48, 1,106,178,219,175,199,166, 48,
			238, 55,204, 36, 31,240, 32, 63, 15, 83, 93,161,116,147, 48,113};
		uint8_t o[64] = {179, 19, 48,202,219,236,232,135,111,155,110, 18, 24,232, 95,158,
			26,110,170,154,109, 42,178,168,156,240,248,238,168,196,190,203,
			69,144, 51, 57, 29, 29,150, 26,150, 30,235,249,190,163,251, 48,
			27,111,114,114,118, 40,152,157,180, 57, 27, 94,107, 42,236, 35};
		salsa20_core(b,b);
		assert_equals(b, o, 64, "SALSA20 CORE");
	}
	{
		uint8_t b[64] = { 6,124, 83,146, 38,191, 9, 50, 4,161, 47,222,122,182,223,185,
			75, 27, 0,216, 16,122, 7, 89,162,104,101,147,213, 21, 54, 95,
			225,253,139,176,105,132, 23,116, 76, 41,176,207,221, 34,157,108,
			94, 94, 99, 52, 90,117, 91,220,146,190,239,143,196,176,130,186};
		uint8_t o[64] = { 8, 18, 38,199,119, 76,215, 67,173,127,144,162,103,212,176,217,
			192, 19,233, 33,159,197,154,160,128,243,219, 65,171,136,135,225,
			123, 11, 68, 86,237, 82, 20,155,133,189, 9, 83,167,116,194, 78,
			122,127,195,185,185,204,188, 90,245, 9,183,248,226, 85,245,104};
		for(uint32_t i = 0; i < 1000000; i++) {
			salsa20_core(b,b);	
		}
		assert_equals(b, o, 64, "SALSA20 CORE");
	}
}

void salsa20_expand_tests() {
	const uint8_t k[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216};
	const uint8_t n[] = {101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116};
	
	const uint8_t o32[] = {
	        69, 37, 68, 39, 41, 15,107,193,255,139,122, 6,170,233,217, 98,
	       89,144,182,106, 21, 51,200, 65,239, 49,222, 34,215,114, 40,126,
	       104,197, 7,225,197,153, 31, 2,102, 78, 76,176, 84,245,246,184,
	       177,160,133,130, 6, 72,149,119,192,195,132,236,234,103,246, 74
	};
	const uint8_t o16[] = {
	        39,173, 46,248, 30,200, 82, 17, 48, 67,254,239, 37, 18, 13,247,
	       241,200, 61,144, 10, 55, 50,185, 6, 47,246,253,143, 86,187,225,
	       134, 85,110,246,161,163, 43,235,231, 94,171, 51,145,214,112, 29,
	       14,232, 5, 16,151,140,183,141,171, 9,122,181,104,182,177,193
	};
	
	uint8_t out[64];
	
	salsa20_expand(k, 32, n, out);
	assert_equals(out, o32, 64, "SALSA20 EXPANSION");
	salsa20_expand(k, 16, n, out);
	assert_equals(out, o16, 64, "SALSA20 EXPANSION");
}

void salsa20_full_tests() {
	{
		uint8_t key[16] = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		uint64_t n = 0;
		uint8_t in[64] = {0};
		uint8_t out[64];
		uint8_t expected[64] = {
		0x4D, 0xFA, 0x5E, 0x48, 0x1D, 0xA2, 0x3E, 0xA0, 0x9A, 0x31, 0x02, 0x20, 0x50, 0x85, 0x99, 0x36,
		0xDA, 0x52, 0xFC, 0xEE, 0x21, 0x80, 0x05, 0x16, 0x4F, 0x26, 0x7C, 0xB6, 0x5F, 0x5C, 0xFD, 0x7F,
		0x2B, 0x4F, 0x97, 0xE0, 0xFF, 0x16, 0x92, 0x4A, 0x52, 0xDF, 0x26, 0x95, 0x15, 0x11, 0x0A, 0x07,
		0xF9, 0xE4, 0x60, 0xBC, 0x65, 0xEF, 0x95, 0xDA, 0x58, 0xF7, 0x40, 0xB7, 0xD1, 0xDB, 0xB0, 0xAA, };
		salsa20_enc(key, 16, n, in, out, 64);
		assert_equals(out, expected, 64, "SALSA20 128 BIT KEY");
	}
	{
		uint8_t key[16] = { 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, };
		uint64_t n = 0;
		uint8_t in[64] = {0};
		uint8_t out[64];
		uint8_t expected[64] = {
		0x05, 0x83, 0x57, 0x54, 0xA1, 0x33, 0x37, 0x70, 0xBB, 0xA8, 0x26, 0x2F, 0x8A, 0x84, 0xD0, 0xFD,
		0x70, 0xAB, 0xF5, 0x8C, 0xDB, 0x83, 0xA5, 0x41, 0x72, 0xB0, 0xC0, 0x7B, 0x6C, 0xCA, 0x56, 0x41,
		0x06, 0x0E, 0x30, 0x97, 0xD2, 0xB1, 0x9F, 0x82, 0xE9, 0x18, 0xCB, 0x69, 0x7D, 0x0F, 0x34, 0x7D,
		0xC7, 0xDA, 0xE0, 0x5C, 0x14, 0x35, 0x5D, 0x09, 0xB6, 0x1B, 0x47, 0x29, 0x8F, 0xE8, 0x9A, 0xEB, };
		salsa20_enc(key, 16, n, in, out, 64);
		assert_equals(out, expected, 64, "SALSA20 128 BIT KEY");
	}
	{
		uint8_t key[32] = { 0x0A, 0x5D, 0xB0, 0x03, 0x56, 0xA9, 0xFC, 0x4F, 0xA2, 0xF5, 0x48, 0x9B, 0xEE, 0x41, 0x94, 0xE7,
                      0x3A, 0x8D, 0xE0, 0x33, 0x86, 0xD9, 0x2C, 0x7F, 0xD2, 0x25, 0x78, 0xCB, 0x1E, 0x71, 0xC4, 0x17, };
		uint64_t n = 17332422828891145759LLU;
		uint8_t in[64] = {0};
		uint8_t out[64];
		uint8_t expected[64] = {
			0x3F, 0xE8, 0x5D, 0x5B, 0xB1, 0x96, 0x0A, 0x82, 0x48, 0x0B, 0x5E, 0x6F, 0x4E, 0x96, 0x5A, 0x44,
			    0x60, 0xD7, 0xA5, 0x45, 0x01, 0x66, 0x4F, 0x7D, 0x60, 0xB5, 0x4B, 0x06, 0x10, 0x0A, 0x37, 0xFF,
			    0xDC, 0xF6, 0xBD, 0xE5, 0xCE, 0x3F, 0x48, 0x86, 0xBA, 0x77, 0xDD, 0x5B, 0x44, 0xE9, 0x56, 0x44,
			    0xE4, 0x0A, 0x8A, 0xC6, 0x58, 0x01, 0x15, 0x5D, 0xB9, 0x0F, 0x02, 0x52, 0x2B, 0x64, 0x40, 0x23,};
		salsa20_enc(key, 32, n, in, out, 64);
		assert_equals(out, expected, 64, "SALSA20 128 BIT KEY");
	}
}

void salsa20_tests() {
	salsa20_core_tests();
	salsa20_expand_tests();
	salsa20_full_tests();
}
