#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../src/runtime/verify_cert.h"
#include "../src/runtime/sha256.h"

typedef struct {
    uint64_t counter;
    int      latch_valid;
    uint8_t  latch[32];
} fuzz_platform_t;

static uint64_t fz_read_epoch(void *ctx) {
    return ((fuzz_platform_t *)ctx)->counter;
}

static int fz_advance_epoch(void *ctx, uint64_t epoch) {
    fuzz_platform_t *p = ctx;
    if (epoch <= p->counter) return 0;
    p->counter = epoch;
    return 1;
}

static int fz_read_attestation(void *ctx, uint8_t digest[32]) {
    fuzz_platform_t *p = ctx;
    if (!p->latch_valid) return 0;
    memcpy(digest, p->latch, 32);
    return 1;
}

// Input: 512-byte cert, then optionally 8 bytes of stored epoch (big-endian),
// then optionally one flag byte. If the flag's low bit is set, the harness
// simulates a successful root-of-trust attestation of this cert, so the
// fuzzer also exercises the post-attestation checks; otherwise nothing is
// latched and every input must be rejected. Ed25519 is off-path and not
// fuzzed here.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < HP_CERT_SIZE) return 0;

    uint8_t cert[HP_CERT_SIZE];
    memcpy(cert, data, HP_CERT_SIZE);

    fuzz_platform_t plat;
    memset(&plat, 0, sizeof(plat));
    for (size_t i = HP_CERT_SIZE; i < size && i < HP_CERT_SIZE + 8; ++i) {
        plat.counter = (plat.counter << 8) | data[i];
    }
    if (size > HP_CERT_SIZE + 8 && (data[HP_CERT_SIZE + 8] & 1)) {
        sha256(cert, HP_CERT_SIZE, plat.latch);
        plat.latch_valid = 1;
    }

    hp_anchor_t anchor;
    memset(&anchor, 0, sizeof(anchor));
    anchor.max_wcet_ns = 150000;
    anchor.max_budget = 10000;
    anchor.max_agents = 10;
    anchor.max_leakage = 100;
    anchor.read_epoch = fz_read_epoch;
    anchor.advance_epoch = fz_advance_epoch;
    anchor.read_attestation = fz_read_attestation;
    anchor.ctx = &plat;

    uint64_t before = plat.counter;
    int accepted = hp_accept_cert(cert, &anchor);

    // Invariants: nothing unattested is accepted; the counter moves only on
    // accept, and only forward
    if (accepted && !plat.latch_valid) __builtin_trap();
    if (!accepted && plat.counter != before) __builtin_trap();
    if (accepted && plat.counter <= before) __builtin_trap();

    return 0;
}
