#ifndef IBCRYPT_MISC_ZFREE_H
#define IBCRYPT_MISC_ZFREE_H

#include <stdlib.h>

/* replica of memset
 * casts p to a volatile pointer and then manually memsets, hopefully avoiding
 * being optimized out */
void *memsets(void *p, int v, size_t n);
/* frees p after setting it to 0 using memset_s */
void zfree(void *p, size_t n);

#endif

