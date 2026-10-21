// tests/test_verify.c
// Unit tests for the verifier. Exits non-zero if any case fails.
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../src/runtime/verify_cert.h"

static int failures = 0;

static void put_be64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        p[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
}

static void check(const char *name, int got, int expected) {
    printf("%-40s %d (expected %d)%s\n", name, got, expected,
           got == expected ? "" : "  <-- FAIL");
    if (got != expected) failures++;
}

// helper to build a valid cert in memory (key_id zeros, epoch 7)
static void build_valid_cert(uint8_t cert[HP_CERT_SIZE]) {
    memset(cert, 0, HP_CERT_SIZE);
    put_be64(cert + HP_OFF_WCET, 150000ull);
    put_be64(cert + HP_OFF_BUDGET, 1000ull);
    cert[HP_OFF_AGENTS] = 5;
    cert[HP_OFF_LEAKAGE] = 50;
    put_be64(cert + HP_OFF_EPOCH, 7ull);
}

int main(void) {
    hp_anchor_t anchor;
    memset(anchor.key_id, 0, sizeof(anchor.key_id));
    anchor.max_wcet_ns = 150000ull;
    anchor.max_budget = 10000ull;
    anchor.max_agents = 5;
    anchor.max_leakage = 100;

    uint8_t cert[HP_CERT_SIZE];
    build_valid_cert(cert);

    check("valid", verify_cert(cert, &anchor, 6), 1);
    check("hp_cert_epoch", (int)hp_cert_epoch(cert), 7);

    // Tamper key_id
    cert[0] = 1;
    check("tampered key_id", verify_cert(cert, &anchor, 6), 0);
    build_valid_cert(cert);

    // Ceilings
    put_be64(cert + HP_OFF_WCET, 150001ull);
    check("wcet over ceiling", verify_cert(cert, &anchor, 6), 0);
    build_valid_cert(cert);

    put_be64(cert + HP_OFF_BUDGET, 10001ull);
    check("budget over ceiling", verify_cert(cert, &anchor, 6), 0);
    build_valid_cert(cert);

    cert[HP_OFF_AGENTS] = 6;
    check("agents over ceiling", verify_cert(cert, &anchor, 6), 0);
    build_valid_cert(cert);

    cert[HP_OFF_LEAKAGE] = 100;
    check("leakage at ceiling", verify_cert(cert, &anchor, 6), 1);
    cert[HP_OFF_LEAKAGE] = 101;
    check("leakage over ceiling", verify_cert(cert, &anchor, 6), 0);
    build_valid_cert(cert);

    // Replay: same epoch as the last accepted one
    check("replay (epoch == last)", verify_cert(cert, &anchor, 7), 0);

    // Downgrade: older cert with a larger leakage value, after epoch 7 was accepted
    put_be64(cert + HP_OFF_EPOCH, 3ull);
    cert[HP_OFF_LEAKAGE] = 90;
    check("downgrade (older epoch, larger leakage)", verify_cert(cert, &anchor, 7), 0);
    build_valid_cert(cert);

    // Epoch boundaries
    put_be64(cert + HP_OFF_EPOCH, 0ull);
    check("epoch 0, last 0", verify_cert(cert, &anchor, 0), 0);
    put_be64(cert + HP_OFF_EPOCH, UINT64_MAX);
    check("epoch max, last max-1", verify_cert(cert, &anchor, UINT64_MAX - 1), 1);
    check("epoch max, last max", verify_cert(cert, &anchor, UINT64_MAX), 0);
    put_be64(cert + HP_OFF_EPOCH, 1ull);
    check("epoch 1, last max (no wraparound)", verify_cert(cert, &anchor, UINT64_MAX), 0);
    build_valid_cert(cert);

    // Large values across the u64 sign bit
    anchor.max_wcet_ns = UINT64_MAX;
    put_be64(cert + HP_OFF_WCET, 0x8000000000000000ull);
    check("wcet high bit, ceiling max", verify_cert(cert, &anchor, 6), 1);
    anchor.max_wcet_ns = 0x7FFFFFFFFFFFFFFFull;
    check("wcet high bit, ceiling below", verify_cert(cert, &anchor, 6), 0);

    if (failures) {
        printf("%d test(s) FAILED\n", failures);
        return 1;
    }
    printf("All tests passed.\n");
    return 0;
}
