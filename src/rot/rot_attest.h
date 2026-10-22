// src/rot/rot_attest.h
// Reference root-of-trust attestation (off-path).
//
// Runs on the root-of-trust (a separate core or secure element), NOT on the
// bounded verifier path: Ed25519 verification is not trivially constant-time
// and has no WCET bound here. The public key lives in the RoT's OTP; the
// latch it writes must be readable by the verifier and writable only by the
// RoT. This reference uses libsodium's crypto_sign_verify_detached.
#ifndef ROT_ATTEST_H
#define ROT_ATTEST_H
#include <stdint.h>
#include "../runtime/verify_cert.h"

typedef struct {
    int     valid;       // 1 if digest holds a verified attestation
    uint8_t digest[32];  // SHA-256 of all 512 cert bytes
} hp_rot_latch_t;

// Verifies the Ed25519 signature at 0x1C0 over bytes 0x000..0x1BF with
// pubkey. On success latches SHA-256 of the full certificate and returns 1.
// On failure clears the latch and returns 0, so a stale attestation never
// survives a failed one.
int hp_rot_attest(const uint8_t cert[HP_CERT_SIZE],
                  const uint8_t pubkey[32],
                  hp_rot_latch_t *latch);

#endif // ROT_ATTEST_H
