// src/rot/rot_attest.c
// Reference root-of-trust attestation using libsodium (off-path).

#include "rot_attest.h"
#include <string.h>
#include <sodium.h>

int hp_rot_attest(const uint8_t cert[HP_CERT_SIZE],
                  const uint8_t pubkey[32],
                  hp_rot_latch_t *latch)
{
    latch->valid = 0;
    memset(latch->digest, 0, sizeof(latch->digest));

    if (sodium_init() < 0) return 0;

    if (crypto_sign_verify_detached(cert + HP_OFF_SIG,
                                    cert, HP_OFF_SIG,
                                    pubkey) != 0) {
        return 0;
    }

    // libsodium's SHA-256, independent of src/runtime/sha256.c: the verifier
    // only accepts if both implementations agree on the digest.
    crypto_hash_sha256(latch->digest, cert, HP_CERT_SIZE);
    latch->valid = 1;
    return 1;
}
