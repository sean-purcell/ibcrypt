#ifndef IBUR_TEST_H
#define IBUR_TEST_H

/**
 * A set of functions to facilitate testing
 * Header for test.c
 */

#include <stdint.h>

void assert_equals(const uint8_t* const a, const uint8_t* const b, int len, const char* const message);

// count completed tests
uint32_t count_tests();
void reset_tests();


#endif
