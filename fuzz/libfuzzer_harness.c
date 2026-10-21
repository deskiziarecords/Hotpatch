#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../src/runtime/verify_cert.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < HP_CERT_SIZE) return 0;

    hp_anchor_t anchor;
    memset(anchor.key_id, 0, sizeof(anchor.key_id));
    anchor.max_wcet_ns = 150000;
    anchor.max_budget = 10000;
    anchor.max_agents = 10;
    anchor.max_leakage = 100;

    // Bytes past the certificate pick last_epoch, so the fuzzer explores the
    // replay boundary too; with no extra bytes, last_epoch is 0.
    uint64_t last_epoch = 0;
    for (size_t i = HP_CERT_SIZE; i < size && i < HP_CERT_SIZE + 8; ++i) {
        last_epoch = (last_epoch << 8) | data[i];
    }

    verify_cert(data, &anchor, last_epoch);

    return 0;
}
