// src/runtime/verify_cert.c
// Constant-time, WCET-friendly verifier for 512-byte hot-patch certificates.
// - No data-dependent branches in hot path
// - Bytewise loads for safety on unaligned platforms
// - Uses only bitwise ops and integer compares
// Returns 1 on accept, 0 on reject

#include "verify_cert.h"
#include <stdint.h>
#include <stddef.h>

// Big-endian u64 loader (bytewise, defined inline for verifier locality)
static inline uint64_t load_be64(const uint8_t *p) {
    uint64_t v = 0;
    // unrolled for deterministic timing
    v = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
        ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
        ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
        ((uint64_t)p[6] << 8)  |  (uint64_t)p[7];
    return v;
}

// Constant-time <= for u64 returning 1 or 0 (branch-free)
static inline uint32_t ct_leq_u64(uint64_t x, uint64_t y) {
    // x <= y is !(y < x)
    // For unsigned, y < x iff [ (msb_y < msb_x) or (msb_y == msb_x and msb(y-x) == 1) ]
    uint64_t lt = ((~y & x) | (~(y ^ x) & (y - x))) >> 63;
    return (uint32_t)(lt & 1u) ^ 1u;
}

// Constant-time <= for u32 returning 1 or 0 (branch-free)
static inline uint32_t ct_leq_u32(uint32_t x, uint32_t y) {
    uint32_t lt = ((~y & x) | (~(y ^ x) & (y - x))) >> 31;
    return (lt & 1u) ^ 1u;
}

// Constant-time <= for u8 returning 1 or 0 (branch-free)
static inline uint32_t ct_leq_u8(uint8_t x, uint8_t y) {
    return ct_leq_u32((uint32_t)x, (uint32_t)y);
}

// Normalize a nonzero integer to 1, zero stays 0. Branch-free.
static inline uint32_t normalize_bool_u32(uint32_t v) {
    // (v | -v) >> 31 gets the sign bit if any bit is set
    return (v | (0u - v)) >> 31;
}

// Public API
int verify_cert(const uint8_t cert[512],
                const uint8_t expected_pubhash[32],
                uint64_t max_wcet_ns,
                uint64_t max_budget,
                uint8_t max_agents,
                uint8_t max_epsilon)
{
    // Step 1: constant-time 32-byte equality
    uint32_t hash_diff = 0;
    for (size_t i = 0; i < 32; ++i) {
        hash_diff |= (uint32_t)(cert[i] ^ expected_pubhash[i]);
    }
    // hash_ok = (hash_diff == 0) ? 1 : 0
    uint32_t hash_ok = normalize_bool_u32(hash_diff) ^ 1u;

    // Step 2: extract numeric fields (bytewise, big-endian)
    uint64_t wcet = load_be64(cert + 0xB0);
    uint64_t deltaB = load_be64(cert + 0xB8);
    uint8_t A = cert[0xC0];
    uint8_t epsilon = cert[0xC1];
    // All fields are treated as unsigned and compared via ct_leq

    // Step 3: constant-time comparisons
    uint32_t wcet_ok = ct_leq_u64(wcet, max_wcet_ns);
    uint32_t budget_ok = ct_leq_u64(deltaB, max_budget);
    uint32_t agents_ok = ct_leq_u8(A, max_agents);
    uint32_t epsilon_ok = ct_leq_u8(epsilon, max_epsilon);

    // Combine all using bitwise AND (still constant-time)
    uint32_t ok = hash_ok & wcet_ok & budget_ok & agents_ok & epsilon_ok;

    // Ensure return is 1 or 0
    return (int)(ok & 1u);
}
