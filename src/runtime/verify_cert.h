// src/runtime/verify_cert.h
#ifndef VERIFY_CERT_H
#define VERIFY_CERT_H
#include <stdint.h>

// Verifier API:
// cert: pointer to 512-byte certificate buffer
// expected_pubhash: pointer to 32-byte expected public-key hash
// max_wcet_ns: maximum allowed WCET (nanoseconds) embedded in ROM/constant
// max_budget: maximum allowed budget (ΔB) embedded in ROM/constant
// max_agents: maximum allowed A (agents) embedded in ROM/constant
//
// Returns 1 if certificate is accepted, 0 otherwise.
int verify_cert(const uint8_t cert[512],
                const uint8_t expected_pubhash[32],
                uint64_t max_wcet_ns,
                uint64_t max_budget,
                uint8_t max_agents);

#endif // VERIFY_CERT_H
