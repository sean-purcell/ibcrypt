#include <stdlib.h>
#include <stdint.h>

#include <libibur/endian.h>

#define IBCRYPT_BUILD
#include "dh_util.h"
#include "dh.h"
#include "rsa.h"
#undef IBCRYPT_BUILD

int dh_val2wire(DH_VAL *v, uint8_t *out, uint64_t outlen) {
	if(outlen < dh_valwire_bufsize(v)) {
		return -1;
	}
	encbe64(v->x.size * 8, out);
	return i2osp(&out[8], v->x.size * 8, &v->x);
}

int dh_wire2val(uint8_t *in, uint64_t inlen, DH_VAL *v) {
	uint64_t size = decbe64(in);
	if(inlen < size + 8) {
		return -1;
	}

	return os2ip(&v->x, &in[8], size);
}

size_t dh_valwire_bufsize(DH_VAL *v) {
	return v->x.size * 8 + 8;
}

