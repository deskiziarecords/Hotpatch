# Makefile - build verifier and run tests
CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c11
PREFIX = /usr/local
# The reference root-of-trust (src/rot) needs libsodium; the verifier does not.
SODIUM_LIBS = -lsodium

.PHONY: all clean test

all: libverify.a test_verify test_rot

libverify.a: src/runtime/verify_cert.c src/runtime/verify_cert.h src/runtime/sha256.c src/runtime/sha256.h
	$(CC) $(CFLAGS) -c src/runtime/verify_cert.c -o verify_cert.o
	$(CC) $(CFLAGS) -c src/runtime/sha256.c -o sha256.o
	ar rcs libverify.a verify_cert.o sha256.o

test_verify: libverify.a tests/test_verify.c
	$(CC) $(CFLAGS) -I src/runtime tests/test_verify.c libverify.a -o test_verify

test_rot: libverify.a tests/test_rot.c src/rot/rot_attest.c src/rot/rot_attest.h
	$(CC) $(CFLAGS) tests/test_rot.c src/rot/rot_attest.c libverify.a $(SODIUM_LIBS) -o test_rot

test: test_verify test_rot
	./test_verify
	./test_rot

clean:
	rm -f *.o libverify.a test_verify test_rot test_verify.exe test_rot.exe
