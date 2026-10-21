#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../src/runtime/verify_cert.h"
#include "../src/runtime/hmac_sha256.h"

// Fixed test key, matching tools/gen_corpus.py: bytes 0x00..0x1f
static const uint8_t test_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

typedef struct {
    uint64_t counter;
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

static void fz_mac(void *ctx, const uint8_t *msg, size_t len, uint8_t out[32]) {
    (void)ctx;
    hmac_sha256(test_key, sizeof(test_key), msg, len, out);
}

// Input: 512-byte cert, then optionally 8 bytes of stored epoch (big-endian),
// then optionally one flag byte. If the flag's low bit is set, the harness
// re-signs the cert so the fuzzer also exercises the post-MAC checks; with a
// random MAC, every input would be rejected at the MAC step.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < HP_CERT_SIZE) return 0;

    uint8_t cert[HP_CERT_SIZE];
    memcpy(cert, data, HP_CERT_SIZE);

    fuzz_platform_t plat;
    plat.counter = 0;
    for (size_t i = HP_CERT_SIZE; i < size && i < HP_CERT_SIZE + 8; ++i) {
        plat.counter = (plat.counter << 8) | data[i];
    }
    if (size > HP_CERT_SIZE + 8 && (data[HP_CERT_SIZE + 8] & 1)) {
        hmac_sha256(test_key, sizeof(test_key), cert, HP_OFF_MAC, cert + HP_OFF_MAC);
    }

    hp_anchor_t anchor;
    memset(&anchor, 0, sizeof(anchor));
    anchor.max_wcet_ns = 150000;
    anchor.max_budget = 10000;
    anchor.max_agents = 10;
    anchor.max_leakage = 100;
    anchor.read_epoch = fz_read_epoch;
    anchor.advance_epoch = fz_advance_epoch;
    anchor.mac = fz_mac;
    anchor.ctx = &plat;

    uint64_t before = plat.counter;
    int accepted = hp_accept_cert(cert, &anchor);

    // Invariant: the counter moves only on accept, and only forward
    if (!accepted && plat.counter != before) __builtin_trap();
    if (accepted && plat.counter <= before) __builtin_trap();

    return 0;
}
