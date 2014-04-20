CC=gcc
CFLAGS= -g -c -O3 -Wall -std=c99

LIB_HEADERS=aes.h sha256.h rand.h
LIB_OBJECTS=aes.o sha256.o aes_modes.o scrypt.o rand.o util.o

TEST_OBJECTS=$(LIB_OBJECTS) test.o aes_test.o sha256_test.o aes_modes_test.o test_suite.o scrypt_test.o

.PHONY: clean cleanall remake remaketest test all lib

all: lib

lib: bin $(LIB_OBJECTS)
	cp $(LIB_HEADERS) bin/ibcrypt/
	ar -rs bin/libibcrypt.a $(LIB_OBJECTS) 

test: bin $(TEST_OBJECTS)
	gcc $(TEST_OBJECTS) -o bin/test

.c.o:
	$(CC) $(CFLAGS) $< -o $@

bin:
	@mkdir bin
	@mkdir bin/ibcrypt
	
clean:
	rm -rf *.o 
	
cleanall: clean
	rm -rf bin

remake: clean lib

remaketest: clean test

install:
	cp bin/libibcrypt.a /usr/local/lib/
	cp -r bin/ibcrypt /usr/local/include/
