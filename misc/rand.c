#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <libibur/util.h>

#include <rand.h>

/* returns URANDOM_FAIL if unsuccessful, 0 if successful */
int cs_rand(void* _buf, size_t buflen) {
	uint8_t* buf = (uint8_t*) _buf;
	int fd;
	size_t lenread;
	
	if((fd = open("/dev/urandom", O_RDONLY)) == -1) {
		goto err0;
	}
	
	while(buflen > 0) {
		if((lenread = read(fd, buf, buflen)) == 0) {
			/* /dev/urandom should never EOF */
			goto err1;
		}
		if(lenread == -1) {
			/* other error, caller can read errno to figure it out */
			goto err1;
		}
		
		/* might not have read all in one go */
		buf += lenread;
		buflen -= lenread;
	}
	
	while(close(fd) == -1) {
		if(errno != EINTR) { /* if close did not fail due to interrupt */
			goto err0;
		}
	}
	
	return 0;
	
err1: /* error occurred after file open */
	close(fd);
err0: /* opening/closing file failed */
	return URANDOM_FAIL;
}

static uint32_t buf[64];
static uint8_t count = 0;

uint32_t cs_rand_int() {
	if(count == 0) {
		if(cs_rand((uint8_t*) buf, 64 * sizeof(uint32_t)) != 0) {
			return 0;
		}
	}
	uint32_t res = buf[count];
	count++;
	count&=63;
	
	return res;
}

uint32_t cs_rand_int_range(uint32_t top) {
	if(top == 0) {
		return 0;
	}
	errno = 0;
	if(top & (top-1)) {
		const uint32_t mask = (2 << lg(top)) - 1;
		const uint32_t max = ((mask + 1) / top) * top;
		while(1) {
			uint32_t guess = cs_rand_int() & mask;
			if(errno != 0) {
				return 0;
			}
			if(guess < max) {
				return guess % top;
			}
		}
	} else {
		return cs_rand_int() & (top-1);
	}
}

