// src/runtime/verify_cert.h
#ifndef VERIFY_CERT_H
#define VERIFY_CERT_H
#include <stdint.h>
#include <stddef.h>

// Certificate layout (512 bytes, big-endian integers):
//   0x00..0x1F   key_id[32]          must equal anchor->key_id
//   0xB0..0xB7   wcet_ns   (u64)     declared WCET of the patch
//   0xB8..0xBF   budget    (u64)     declared ΔB
//   0xC0         agents    (u8)      declared A
//   0xC1         leakage_attestation (u8)  declared offline leakage value
//   0xC2..0xC9   epoch     (u64)     monotonic; must exceed the stored epoch
//   0x1E0..0x1FF mac[32]             HMAC-SHA256 over bytes 0x000..0x1DF
#define HP_CERT_SIZE        512
#define HP_OFF_KEY_ID       0x00
#define HP_OFF_WCET         0xB0
#define HP_OFF_BUDGET       0xB8
#define HP_OFF_AGENTS       0xC0
#define HP_OFF_LEAKAGE      0xC1
#define HP_OFF_EPOCH        0xC2
#define HP_OFF_MAC          0x1E0
#define HP_MAC_SIZE         32

// Trust anchor: identity, ceilings, and the platform's root-of-trust hooks.
// The platform MUST place this in storage the patched agent cannot write
// (OTP fuses, ROM, or memory locked by the root-of-trust). The verifier
// cannot check that property; it only reads through this pointer.
typedef struct {
    uint8_t  key_id[32];
    uint64_t max_wcet_ns;
    uint64_t max_budget;
    uint8_t  max_agents;
    uint8_t  max_leakage;

    // Monotonic epoch counter. Must be backed by storage the verified agent
    // cannot rewrite (write-once/monotonic NVRAM, OTP counter, RPMB, or a
    // register only the root-of-trust can write). If software can roll it
    // back, replay protection does not hold.
    uint64_t (*read_epoch)(void *ctx);
    // Sets the counter to epoch. Returns 1 on success, 0 on failure. The
    // storage itself must refuse epoch <= current value.
    int (*advance_epoch)(void *ctx, uint64_t epoch);

    // HMAC-SHA256 of msg under a key the agent cannot read (hardware engine
    // with a sealed key). hmac_sha256.h is a software reference for tests.
    void (*mac)(void *ctx, const uint8_t *msg, size_t len, uint8_t out[32]);

    void *ctx;
} hp_anchor_t;

// Pure check, no side effects. Accepts only if the MAC is valid, key_id
// matches, every declared value is within the anchor's ceilings, and
// epoch > anchor->read_epoch() (blocks replay and downgrade).
//
// Returns 1 if certificate is accepted, 0 otherwise.
int verify_cert(const uint8_t cert[HP_CERT_SIZE], const hp_anchor_t *anchor);

// The only path that advances the counter: verifies first (including the
// MAC), then advances the counter to the cert's epoch. A forged cert never
// reaches advance_epoch, so it cannot push the counter to UINT64_MAX and
// brick future updates. Apply the patch only if this returns 1.
//
// Returns 1 if verified and the counter was advanced, 0 otherwise.
int hp_accept_cert(const uint8_t cert[HP_CERT_SIZE], const hp_anchor_t *anchor);

#endif // VERIFY_CERT_H
