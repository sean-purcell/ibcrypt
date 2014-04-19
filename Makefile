CC=gcc
CFLAGS= -g -c -O3 -Wall -std=c99
TEST_OBJECTS=aes.o aes_modes.o sha256.o util.o test.o aes_test.o sha256_test.o aes_modes_test.o test_suite.o

LIB_HEADERS=aes.h sha256.h rand.h
LIB_OBJECTS=aes.o sha256.o util.o aes_modes.o util.o rand.o

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
