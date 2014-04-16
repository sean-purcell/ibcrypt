CC=gcc
CFLAGS= -g -c -O3 -Wall
TEST_SOURCES=aes.o sha256.o util.o test.o aes_test.o sha256_test.o test_suite.o
TEST_OBJECTS=$(TEST_SOURCES:.c=.o)

test: bin $(TEST_OBJECTS)
	gcc $(TEST_SOURCES) -o bin/test

.c.o:
	$(CC) $(CFLAGS) $< -o $@

bin:
	@mkdir bin

clean:
	rm -rf *.o test
