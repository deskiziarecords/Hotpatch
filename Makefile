# Makefile - build verifier and run tests
CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c11
PREFIX = /usr/local

.PHONY: all clean test

all: libverify.a test_verify

libverify.a: src/runtime/verify_cert.c src/runtime/verify_cert.h
	$(CC) $(CFLAGS) -c src/runtime/verify_cert.c -o verify_cert.o
	ar rcs libverify.a verify_cert.o

test_verify: libverify.a tests/test_verify.c
	$(CC) $(CFLAGS) -I src/runtime tests/test_verify.c libverify.a -o test_verify

test: test_verify
	./test_verify

clean:
	rm -f *.o libverify.a test_verify
