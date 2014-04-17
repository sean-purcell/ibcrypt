CC=gcc
CFLAGS= -g -c -O3 -Wall
TEST_OBJECTS=aes.o aes_modes.o sha256.o util.o test.o aes_test.o sha256_test.o aes_modes_test.o test_suite.o

LIB_OBJECTS=aes.o sha256.o util.o aes_modes.o util.o

lib: bin $(LIB_OBJECTS)
	

test: bin $(TEST_OBJECTS)
	gcc $(TEST_OBJECTS) -o bin/test

.c.o:
	$(CC) $(CFLAGS) $< -o $@

bin:
	@mkdir bin

clean:
	rm -rf *.o test
