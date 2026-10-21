// src/runtime/verify_cert.h
#ifndef VERIFY_CERT_H
#define VERIFY_CERT_H
#include <stdint.h>

// Certificate layout (512 bytes, big-endian integers):
//   0x00..0x1F  key_id[32]          must equal anchor->key_id
//   0xB0..0xB7  wcet_ns   (u64)     declared WCET of the patch
//   0xB8..0xBF  budget    (u64)     declared ΔB
//   0xC0        agents    (u8)      declared A
//   0xC1        leakage_attestation (u8)  declared offline leakage value
//   0xC2..0xC9  epoch     (u64)     monotonic; must exceed last accepted epoch
#define HP_CERT_SIZE        512
#define HP_OFF_KEY_ID       0x00
#define HP_OFF_WCET         0xB0
#define HP_OFF_BUDGET       0xB8
#define HP_OFF_AGENTS       0xC0
#define HP_OFF_LEAKAGE      0xC1
#define HP_OFF_EPOCH        0xC2

// Trust anchor: identity and ceilings provisioned at manufacture.
// The platform MUST place this in storage the patched agent cannot write
// (OTP fuses, ROM, or memory locked by the root-of-trust). The verifier
// cannot check that property; it only reads through this pointer.
//
// NOTE: key_id is compared, not verified cryptographically. This is not
// authentication; see README "Trust Anchor".
typedef struct {
    uint8_t  key_id[32];
    uint64_t max_wcet_ns;
    uint64_t max_budget;
    uint8_t  max_agents;
    uint8_t  max_leakage;
} hp_anchor_t;

// Verifier API:
// cert:       512-byte certificate buffer
// anchor:     provisioned trust anchor (see above)
// last_epoch: last accepted epoch, read from a monotonic counter outside the
//             agent's reach (OTP counter, RPMB, or root-of-trust)
//
// Accepts only if key_id matches, every declared value is within the anchor's
// ceilings, and epoch > last_epoch (blocks replay and downgrade to older certs).
// On accept, the caller must advance the monotonic counter to the cert's epoch
// (hp_cert_epoch) before applying the patch.
//
// Returns 1 if certificate is accepted, 0 otherwise.
int verify_cert(const uint8_t cert[HP_CERT_SIZE],
                const hp_anchor_t *anchor,
                uint64_t last_epoch);

// Epoch carried by a certificate (for committing to the monotonic counter).
uint64_t hp_cert_epoch(const uint8_t cert[HP_CERT_SIZE]);

#endif // VERIFY_CERT_H
