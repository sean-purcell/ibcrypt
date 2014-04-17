#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include "rand.h"

// returns URANDOM_FAIL if unsuccessful, 0 if successful
int cs_rand(uint8_t* buf, uint32_t buflen) {
	int fd;
	size_t lenread;
	
	if((fd = open("/dev/urandom", O_RDONLY)) == -1) {
		goto err0;
	}
	
	while(buflen > 0) {
		if((lenread = read(fd, buf, buflen)) == 0) {
			// /dev/urandom should never EOF
			goto err1;
		}
		if(lenread == -1) {
			// other error, caller can read errno to figure it out
			goto err1;
		}
		
		// could not have read all in one go
		buf += lenread;
		buflen -= lenread;
	}
	
	while(close(fd) == -1) {
		if(errno != EINTR) { // if close did not fail due to interrupt
			goto err0;
		}
	}
	
	return 0;
	
err1: // error occurred after file open
	close(fd);
err0: // opening/closing file failed
	return URANDOM_FAIL;
}