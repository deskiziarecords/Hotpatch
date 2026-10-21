// src/runtime/verify_cert.c
// Constant-time, WCET-friendly verifier for 512-byte hot-patch certificates.
// Ceilings, key_id, the epoch counter and the MAC all come from the trust
// anchor; nothing security-relevant is a caller argument.
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
int verify_cert(const uint8_t cert[HP_CERT_SIZE], const hp_anchor_t *anchor)
{
    // Step 0: MAC over everything before the MAC field, constant-time compare
    uint8_t mac[HP_MAC_SIZE];
    anchor->mac(anchor->ctx, cert, HP_OFF_MAC, mac);
    uint32_t mac_diff = 0;
    for (size_t i = 0; i < HP_MAC_SIZE; ++i) {
        mac_diff |= (uint32_t)(cert[HP_OFF_MAC + i] ^ mac[i]);
    }
    uint32_t mac_ok = normalize_bool_u32(mac_diff) ^ 1u;

    // Step 1: constant-time 32-byte equality against the anchor's key_id
    uint32_t key_diff = 0;
    for (size_t i = 0; i < 32; ++i) {
        key_diff |= (uint32_t)(cert[HP_OFF_KEY_ID + i] ^ anchor->key_id[i]);
    }
    // key_ok = (key_diff == 0) ? 1 : 0
    uint32_t key_ok = normalize_bool_u32(key_diff) ^ 1u;
    uint64_t last_epoch = anchor->read_epoch(anchor->ctx);

    // Step 2: extract numeric fields (bytewise, big-endian)
    uint64_t wcet = load_be64(cert + HP_OFF_WCET);
    uint64_t deltaB = load_be64(cert + HP_OFF_BUDGET);
    uint8_t A = cert[HP_OFF_AGENTS];
    uint8_t leakage = cert[HP_OFF_LEAKAGE];
    uint64_t epoch = load_be64(cert + HP_OFF_EPOCH);
    // All fields are treated as unsigned and compared via ct_leq

    // Step 3: constant-time comparisons against the anchor's ceilings
    uint32_t wcet_ok = ct_leq_u64(wcet, anchor->max_wcet_ns);
    uint32_t budget_ok = ct_leq_u64(deltaB, anchor->max_budget);
    uint32_t agents_ok = ct_leq_u8(A, anchor->max_agents);
    uint32_t leakage_ok = ct_leq_u8(leakage, anchor->max_leakage);

    // Step 4: replay/downgrade, epoch > last_epoch is !(epoch <= last_epoch)
    uint32_t epoch_ok = ct_leq_u64(epoch, last_epoch) ^ 1u;

    // Combine all using bitwise AND (still constant-time)
    uint32_t ok = mac_ok & key_ok & wcet_ok & budget_ok & agents_ok & leakage_ok & epoch_ok;

    // Ensure return is 1 or 0
    return (int)(ok & 1u);
}

int hp_accept_cert(const uint8_t cert[HP_CERT_SIZE], const hp_anchor_t *anchor)
{
    // Order matters: authenticate before touching the counter, always.
    // This branch is on the verdict, not on secret data.
    if (!verify_cert(cert, anchor)) return 0;
    return anchor->advance_epoch(anchor->ctx, load_be64(cert + HP_OFF_EPOCH)) == 1;
}
