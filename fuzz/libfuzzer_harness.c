#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../src/runtime/verify_cert.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 512) return 0;

    uint8_t expected_pubhash[32];
    memset(expected_pubhash, 0, 32);

    uint64_t max_wcet_ns = 150000;
    uint64_t max_budget = 10000;
    uint8_t max_agents = 10;
    uint8_t max_epsilon = 100;

    verify_cert(data, expected_pubhash, max_wcet_ns, max_budget, max_agents, max_epsilon);

    return 0;
}
