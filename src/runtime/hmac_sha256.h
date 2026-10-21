// src/runtime/hmac_sha256.h
// Software HMAC-SHA256 reference (FIPS 180-4, RFC 2104).
//
// Used by tests, CI, and the CLI harness as the hp_anchor_t MAC hook. A key
// held in software is readable by anything sharing its address space, so on
// a device the MAC hook should be a hardware engine with a sealed key.
#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H
#include <stdint.h>
#include <stddef.h>

void sha256(const uint8_t *msg, size_t len, uint8_t out[32]);

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t len,
                 uint8_t out[32]);

#endif // HMAC_SHA256_H
