// tests/test_verify.c
// Unit tests for the verifier. Exits non-zero if any case fails.
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../src/runtime/verify_cert.h"
#include "../src/runtime/sha256.h"

static int failures = 0;

static void check(const char *name, int got, int expected) {
    printf("%-48s %d (expected %d)%s\n", name, got, expected,
           got == expected ? "" : "  <-- FAIL");
    if (got != expected) failures++;
}

static void check_hex(const char *name, const uint8_t got[32], const char *expected_hex) {
    char hex[65];
    for (int i = 0; i < 32; ++i) sprintf(hex + 2 * i, "%02x", got[i]);
    int ok = strcmp(hex, expected_hex) == 0;
    printf("%-48s %s\n", name, ok ? "ok" : "FAIL");
    if (!ok) {
        printf("  got      %s\n  expected %s\n", hex, expected_hex);
        failures++;
    }
}

// ---- Simulated platform: monotonic counter + root-of-trust latch ----

typedef struct {
    uint64_t counter;
    int      latch_valid;
    uint8_t  latch[32];
    int      advance_calls;
    int      fail_advance;
} test_platform_t;

static uint64_t tp_read_epoch(void *ctx) {
    return ((test_platform_t *)ctx)->counter;
}

static int tp_advance_epoch(void *ctx, uint64_t epoch) {
    test_platform_t *p = ctx;
    p->advance_calls++;
    // Monotonic storage refuses to go backwards or stay put
    if (p->fail_advance || epoch <= p->counter) return 0;
    p->counter = epoch;
    return 1;
}

static int tp_read_attestation(void *ctx, uint8_t digest[32]) {
    test_platform_t *p = ctx;
    if (!p->latch_valid) return 0;
    memcpy(digest, p->latch, 32);
    return 1;
}

static void put_be64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        p[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
}

// Simulates the root-of-trust after a successful signature check: latches
// SHA-256 of the cert. Ed25519 itself is tested in tests/test_rot.c.
static void sign_cert(uint8_t cert[HP_CERT_SIZE], test_platform_t *p) {
    sha256(cert, HP_CERT_SIZE, p->latch);
    p->latch_valid = 1;
}

// helper to build a valid, attested cert in memory (key_id zeros, epoch 7)
static void build_valid_cert(uint8_t cert[HP_CERT_SIZE], test_platform_t *p) {
    memset(cert, 0, HP_CERT_SIZE);
    put_be64(cert + HP_OFF_WCET, 150000ull);
    put_be64(cert + HP_OFF_BUDGET, 1000ull);
    cert[HP_OFF_AGENTS] = 5;
    cert[HP_OFF_LEAKAGE] = 50;
    put_be64(cert + HP_OFF_EPOCH, 7ull);
    sign_cert(cert, p);
}

static void test_sha256_vectors(void) {
    uint8_t out[32];

    sha256((const uint8_t *)"", 0, out);
    check_hex("SHA-256 \"\"", out,
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    sha256((const uint8_t *)"abc", 3, out);
    check_hex("SHA-256 \"abc\"", out,
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    const char *m56 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256((const uint8_t *)m56, strlen(m56), out);
    check_hex("SHA-256 56-byte (two-block padding)", out,
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

int main(void) {
    test_sha256_vectors();

    test_platform_t plat;
    memset(&plat, 0, sizeof(plat));
    plat.counter = 6;

    hp_anchor_t anchor;
    memset(&anchor, 0, sizeof(anchor));
    anchor.max_wcet_ns = 150000ull;
    anchor.max_budget = 10000ull;
    anchor.max_agents = 5;
    anchor.max_leakage = 100;
    anchor.read_epoch = tp_read_epoch;
    anchor.advance_epoch = tp_advance_epoch;
    anchor.read_attestation = tp_read_attestation;
    anchor.ctx = &plat;

    uint8_t cert[HP_CERT_SIZE];
    build_valid_cert(cert, &plat);

    check("valid", verify_cert(cert, &anchor), 1);

    // Attestation
    plat.latch_valid = 0;
    check("nothing latched", verify_cert(cert, &anchor), 0);
    build_valid_cert(cert, &plat);

    memset(plat.latch, 0, sizeof(plat.latch));
    check("latch valid, zero digest", verify_cert(cert, &anchor), 0);
    build_valid_cert(cert, &plat);

    cert[0x50] ^= 1;
    check("byte changed after attestation (TOCTOU)", verify_cert(cert, &anchor), 0);
    build_valid_cert(cert, &plat);

    cert[HP_OFF_SIG] ^= 1;
    check("signature byte changed after attestation", verify_cert(cert, &anchor), 0);
    build_valid_cert(cert, &plat);

    cert[HP_OFF_LEAKAGE] = 10;
    check("lowered leakage, not re-attested", verify_cert(cert, &anchor), 0);
    build_valid_cert(cert, &plat);

    // key_id (re-attested, so only the key_id check can reject it)
    cert[0] = 1;
    sign_cert(cert, &plat);
    check("wrong key_id, attested", verify_cert(cert, &anchor), 0);
    build_valid_cert(cert, &plat);

    // Ceilings (re-attested)
    put_be64(cert + HP_OFF_WCET, 150001ull);
    sign_cert(cert, &plat);
    check("wcet over ceiling", verify_cert(cert, &anchor), 0);
    build_valid_cert(cert, &plat);

    put_be64(cert + HP_OFF_BUDGET, 10001ull);
    sign_cert(cert, &plat);
    check("budget over ceiling", verify_cert(cert, &anchor), 0);
    build_valid_cert(cert, &plat);

    cert[HP_OFF_AGENTS] = 6;
    sign_cert(cert, &plat);
    check("agents over ceiling", verify_cert(cert, &anchor), 0);
    build_valid_cert(cert, &plat);

    cert[HP_OFF_LEAKAGE] = 100;
    sign_cert(cert, &plat);
    check("leakage at ceiling", verify_cert(cert, &anchor), 1);
    cert[HP_OFF_LEAKAGE] = 101;
    sign_cert(cert, &plat);
    check("leakage over ceiling", verify_cert(cert, &anchor), 0);
    build_valid_cert(cert, &plat);

    // Large values across the u64 sign bit
    anchor.max_wcet_ns = UINT64_MAX;
    put_be64(cert + HP_OFF_WCET, 0x8000000000000000ull);
    sign_cert(cert, &plat);
    check("wcet high bit, ceiling max", verify_cert(cert, &anchor), 1);
    anchor.max_wcet_ns = 0x7FFFFFFFFFFFFFFFull;
    check("wcet high bit, ceiling below", verify_cert(cert, &anchor), 0);
    anchor.max_wcet_ns = 150000ull;
    build_valid_cert(cert, &plat);

    // ---- hp_accept_cert: counter only moves after authentication ----

    // Brick attempt: forged epoch UINT64_MAX; the latch still holds the
    // digest of the original cert, since the RoT never attested the forgery
    put_be64(cert + HP_OFF_EPOCH, UINT64_MAX);
    plat.advance_calls = 0;
    check("accept forged epoch=UINT64_MAX", hp_accept_cert(cert, &anchor), 0);
    check("  advance_epoch not called", plat.advance_calls, 0);
    check("  counter unchanged", plat.counter == 6, 1);
    build_valid_cert(cert, &plat);

    // Rejected on a ceiling: counter must not move either
    cert[HP_OFF_AGENTS] = 6;
    sign_cert(cert, &plat);
    check("accept over-ceiling cert", hp_accept_cert(cert, &anchor), 0);
    check("  advance_epoch not called", plat.advance_calls, 0);
    build_valid_cert(cert, &plat);

    // Storage failure: accept must report failure
    plat.fail_advance = 1;
    check("accept when advance_epoch fails", hp_accept_cert(cert, &anchor), 0);
    check("  counter unchanged", plat.counter == 6, 1);
    plat.fail_advance = 0;

    // Normal accept advances the counter
    check("accept valid (epoch 7 > 6)", hp_accept_cert(cert, &anchor), 1);
    check("  counter advanced to 7", plat.counter == 7, 1);

    // Replay: the same cert again
    check("replay same cert", hp_accept_cert(cert, &anchor), 0);
    check("  counter still 7", plat.counter == 7, 1);

    // Downgrade: older, validly signed cert with a larger leakage value
    put_be64(cert + HP_OFF_EPOCH, 3ull);
    cert[HP_OFF_LEAKAGE] = 90;
    sign_cert(cert, &plat);
    check("downgrade (epoch 3, larger leakage)", hp_accept_cert(cert, &anchor), 0);
    build_valid_cert(cert, &plat);

    // Epoch boundaries
    put_be64(cert + HP_OFF_EPOCH, UINT64_MAX);
    sign_cert(cert, &plat);
    plat.counter = UINT64_MAX - 1;
    check("epoch max, counter max-1", verify_cert(cert, &anchor), 1);
    plat.counter = UINT64_MAX;
    check("epoch max, counter max", verify_cert(cert, &anchor), 0);
    put_be64(cert + HP_OFF_EPOCH, 1ull);
    sign_cert(cert, &plat);
    check("epoch 1, counter max (no wraparound)", verify_cert(cert, &anchor), 0);

    if (failures) {
        printf("%d test(s) FAILED\n", failures);
        return 1;
    }
    printf("All tests passed.\n");
    return 0;
}
