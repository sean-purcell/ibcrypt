#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <libibur/util.h>

#include "rand.h"

static uint8_t random_buf[1024];
static const size_t RANDOM_BUFLEN = 1024;
static size_t buf_index = 0;
static pthread_mutex_t rand_mutex = PTHREAD_MUTEX_INITIALIZER;
/* set to 0 after the first use */
static int random_init = 1;

static int reset_buf() {
	buf_index = 0;
	
	size_t len = RANDOM_BUFLEN;
	int ur_fd;
	size_t lenread;
	size_t index = 0;
	if((ur_fd = open("/dev/urandom", O_RDONLY)) == -1) {
		goto err0;
	}

	while(len > 0) {
		if((lenread = read(ur_fd, &random_buf[index], len)) == 0) {
			/* urandom should never EOF */
			goto err1;
		}

		if(lenread == -1) {
			/* other error, caller can read errno to figure it out */
			goto err1;
		}

		/* might not have read all in one go */
		index += lenread;
		len -= lenread;
	}

	while(close(ur_fd) == -1) {
		/* close might have failed from interrupt */
		if(errno != EINTR) {
			goto err0;
		}
	}

	return 0;

err1: /* error occurred after file open */
	close(ur_fd);
err0: /* error occurred while closing/opening fd */
	return RANDOM_FAIL;
}

/* returns RANDOM_FAIL if unsuccessful, 0 if successful */
int cs_rand(void *_buf, size_t buflen) {
	pthread_mutex_lock(&rand_mutex);
	if(random_init) {
		reset_buf();
		random_init = 0;
	}
	uint8_t *buf = (uint8_t*) _buf;
	size_t space = RANDOM_BUFLEN - buf_index;
	while(buflen >= space) {
		memcpy(buf, &random_buf[buf_index], space * sizeof(uint8_t));
		buf += space;
		buflen -= space;

		if(reset_buf() != 0) {
			return RANDOM_FAIL;
		}
		space = RANDOM_BUFLEN;
	}

	memcpy(buf, &random_buf[buf_index], buflen);
	buf_index += buflen;

	pthread_mutex_unlock(&rand_mutex);
	return 0;
}

int cs_rand_uint64(uint64_t *r) {
	return cs_rand(r, sizeof(uint64_t));
}

int cs_rand_uint64_range(uint64_t *r, uint64_t top) {
	if(top == 0) {
		*r = 0;
		return 0;
	}
	uint64_t guess;
	if(top & (top-1)) {
		const uint64_t mask = (2 << lg(top)) - 1;
		while(1) {
			if(cs_rand_uint64(&guess) != 0) {
				return RANDOM_FAIL;
			}
			guess = guess & mask;
			if(guess < top) {
				*r = guess;
				return 0;
			}
		}
	} else {
		if(cs_rand_uint64(&guess) != 0) {
			return RANDOM_FAIL;
		}
		*r = guess & (top - 1);
		return 0;
	}
}

int cs_rand_uint32(uint32_t *r) {
	return cs_rand(r, sizeof(uint32_t));
}

int cs_rand_uint32_range(uint32_t *r, uint32_t top) {
	uint64_t res;
	if(cs_rand_uint64_range(&res, (uint64_t) top) != 0) {
		return RANDOM_FAIL;
	}

	*r = (uint32_t) res;
	return 0;
}

