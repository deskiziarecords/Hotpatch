// src/runtime/sha256.h
// SHA-256 (FIPS 180-4) for the bounded path: hashes the certificate so it can
// be compared against the root-of-trust's latched attestation digest.
#ifndef SHA256_H
#define SHA256_H
#include <stdint.h>
#include <stddef.h>

void sha256(const uint8_t *msg, size_t len, uint8_t out[32]);

#endif // SHA256_H
