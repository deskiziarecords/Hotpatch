// tests/test_rot.c
// Tests for the reference root-of-trust (Ed25519 via libsodium) and the full
// sign -> attest -> hp_accept_cert flow. Exits non-zero if any case fails.
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sodium.h>
#include "../src/runtime/verify_cert.h"
#include "../src/runtime/sha256.h"
#include "../src/rot/rot_attest.h"

static int failures = 0;

static void check(const char *name, int got, int expected) {
    printf("%-48s %d (expected %d)%s\n", name, got, expected,
           got == expected ? "" : "  <-- FAIL");
    if (got != expected) failures++;
}

static void hex_decode(const char *hex, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        unsigned v;
        sscanf(hex + 2 * i, "%02x", &v);
        out[i] = (uint8_t)v;
    }
}

static void put_be64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        p[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
}

// Platform: monotonic counter + the RoT latch
typedef struct {
    uint64_t       counter;
    hp_rot_latch_t latch;
} rot_platform_t;

static uint64_t rp_read_epoch(void *ctx) {
    return ((rot_platform_t *)ctx)->counter;
}

static int rp_advance_epoch(void *ctx, uint64_t epoch) {
    rot_platform_t *p = ctx;
    if (epoch <= p->counter) return 0;
    p->counter = epoch;
    return 1;
}

static int rp_read_attestation(void *ctx, uint8_t digest[32]) {
    rot_platform_t *p = ctx;
    if (!p->latch.valid) return 0;
    memcpy(digest, p->latch.digest, 32);
    return 1;
}

// Offline signer stand-in (tools/sign_cert.py does the same with Python)
static void sign(uint8_t cert[HP_CERT_SIZE], const uint8_t sk[64]) {
    crypto_sign_detached(cert + HP_OFF_SIG, NULL, cert, HP_OFF_SIG, sk);
}

static void build_cert(uint8_t cert[HP_CERT_SIZE], uint64_t epoch, const uint8_t sk[64]) {
    memset(cert, 0, HP_CERT_SIZE);
    put_be64(cert + HP_OFF_WCET, 100000ull);
    put_be64(cert + HP_OFF_BUDGET, 1000ull);
    cert[HP_OFF_AGENTS] = 5;
    cert[HP_OFF_LEAKAGE] = 50;
    put_be64(cert + HP_OFF_EPOCH, epoch);
    sign(cert, sk);
}

int main(void) {
    if (sodium_init() < 0) {
        printf("sodium_init failed\n");
        return 1;
    }

    // RFC 8032 section 7.1, TEST 1: empty message
    uint8_t rfc_pk[32], rfc_sig[64];
    hex_decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", rfc_pk, 32);
    hex_decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065"
               "224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
               rfc_sig, 64);
    check("RFC 8032 TEST 1 verifies",
          crypto_sign_verify_detached(rfc_sig, (const uint8_t *)"", 0, rfc_pk) == 0, 1);

    // Test keypair from fixed seed 00..1f (test only)
    uint8_t seed[32], pk[32], sk[64];
    for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)i;
    crypto_sign_seed_keypair(pk, sk, seed);

    uint8_t other_pk[32], other_sk[64];
    seed[0] = 0xff;
    crypto_sign_seed_keypair(other_pk, other_sk, seed);

    uint8_t cert[HP_CERT_SIZE];
    hp_rot_latch_t latch;

    // ---- RoT attestation ----
    build_cert(cert, 7, sk);
    check("attest valid signature", hp_rot_attest(cert, pk, &latch), 1);
    uint8_t ours[32];
    sha256(cert, HP_CERT_SIZE, ours);
    check("  latched digest == runtime sha256 (libsodium)", memcmp(ours, latch.digest, 32) == 0, 1);

    cert[0x50] ^= 1;
    check("attest tampered body", hp_rot_attest(cert, pk, &latch), 0);
    check("  latch cleared (stale attestation gone)", latch.valid, 0);
    build_cert(cert, 7, sk);

    cert[HP_OFF_SIG + 10] ^= 1;
    check("attest tampered signature", hp_rot_attest(cert, pk, &latch), 0);
    build_cert(cert, 7, sk);

    check("attest with wrong public key", hp_rot_attest(cert, other_pk, &latch), 0);

    build_cert(cert, 7, other_sk);
    check("attest cert signed by other key", hp_rot_attest(cert, pk, &latch), 0);

    // ---- End to end: sign -> attest -> hp_accept_cert ----
    rot_platform_t plat;
    memset(&plat, 0, sizeof(plat));
    plat.counter = 6;

    hp_anchor_t anchor;
    memset(&anchor, 0, sizeof(anchor));
    anchor.max_wcet_ns = 150000ull;
    anchor.max_budget = 10000ull;
    anchor.max_agents = 5;
    anchor.max_leakage = 100;
    anchor.read_epoch = rp_read_epoch;
    anchor.advance_epoch = rp_advance_epoch;
    anchor.read_attestation = rp_read_attestation;
    anchor.ctx = &plat;

    build_cert(cert, 7, sk);
    hp_rot_attest(cert, pk, &plat.latch);
    check("e2e accept (epoch 7 > 6)", hp_accept_cert(cert, &anchor), 1);
    check("  counter advanced to 7", plat.counter == 7, 1);
    check("e2e replay same cert", hp_accept_cert(cert, &anchor), 0);

    // Brick attempt: attacker sets epoch to UINT64_MAX on a validly signed cert
    build_cert(cert, 8, sk);
    put_be64(cert + HP_OFF_EPOCH, UINT64_MAX);
    check("e2e forged epoch=UINT64_MAX: RoT refuses", hp_rot_attest(cert, pk, &plat.latch), 0);
    check("  hp_accept_cert refuses", hp_accept_cert(cert, &anchor), 0);
    check("  counter still 7", plat.counter == 7, 1);

    // Swap after attestation: attest a good cert, present a different one
    build_cert(cert, 8, sk);
    hp_rot_attest(cert, pk, &plat.latch);
    uint8_t swapped[HP_CERT_SIZE];
    build_cert(swapped, 9, sk);
    check("e2e cert swapped after attestation", hp_accept_cert(swapped, &anchor), 0);
    check("e2e attested cert still accepted", hp_accept_cert(cert, &anchor), 1);
    check("  counter advanced to 8", plat.counter == 8, 1);

    if (failures) {
        printf("%d test(s) FAILED\n", failures);
        return 1;
    }
    printf("All RoT tests passed.\n");
    return 0;
}
