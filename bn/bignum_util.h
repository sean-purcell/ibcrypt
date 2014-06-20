/* this file should not be released as part of the API,
 * it is purely for internal use */

#ifndef IBCRYPT_BN_BIGNUM_UTIL_H
#define IBCRYPT_BN_BIGNUM_UTIL_H

#include <stdint.h>

int bnu_resize(BIGNUM* r, uint32_t size);

#endif
