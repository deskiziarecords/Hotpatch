#!/usr/bin/env python3
import os

# Seed format, matching fuzz/libfuzzer_harness.c: 512-byte cert, 8-byte stored
# epoch (big-endian), then a flag byte whose low bit makes the harness
# simulate a successful root-of-trust attestation of the cert.

def make_cert(wcet, budget, agents, leakage, epoch=1, key_id=None):
    cert = bytearray(512)
    if key_id:
        cert[0:32] = key_id
    cert[0xB0:0xB0+8] = wcet.to_bytes(8, 'big')
    cert[0xB8:0xB8+8] = budget.to_bytes(8, 'big')
    cert[0xC0] = agents
    cert[0xC1] = leakage
    cert[0xC2:0xC2+8] = epoch.to_bytes(8, 'big')
    return cert

def seed(cert, stored_epoch=0, attested=True):
    return bytes(cert) + stored_epoch.to_bytes(8, 'big') + bytes([1 if attested else 0])

def main():
    corpus_dir = "fuzz_corpus"
    if not os.path.exists(corpus_dir):
        os.makedirs(corpus_dir)

    def write(name, data):
        with open(os.path.join(corpus_dir, name), "wb") as f:
            f.write(data)

    # Valid cert
    write("valid_1", seed(make_cert(100000, 5000, 5, 50)))

    # Boundary certs
    write("boundary_wcet", seed(make_cert(150000, 5000, 5, 50)))
    write("boundary_budget", seed(make_cert(100000, 10000, 5, 50)))
    write("boundary_agents", seed(make_cert(100000, 5000, 10, 50)))
    write("boundary_leakage", seed(make_cert(100000, 5000, 5, 100)))

    # Invalid certs
    write("invalid_wcet", seed(make_cert(200000, 5000, 5, 50)))

    # Replay seed: epoch 0 never exceeds the stored epoch
    write("replay_epoch0", seed(make_cert(100000, 5000, 5, 50, epoch=0)))

    # Epoch boundary: cert epoch 7, stored epoch 6 (accept) and 7 (reject)
    write("epoch_boundary_accept", seed(make_cert(100000, 5000, 5, 50, epoch=7), stored_epoch=6))
    write("epoch_boundary_replay", seed(make_cert(100000, 5000, 5, 50, epoch=7), stored_epoch=7))

    # Forged brick attempt: epoch u64 max, never attested
    write("forged_epoch_max", seed(make_cert(100000, 5000, 5, 50, epoch=2**64 - 1), attested=False))

    # Bare 512-byte cert: no stored epoch, no attestation
    write("bare_unattested", bytes(make_cert(100000, 5000, 5, 50)))

    print(f"Generated corpus in {corpus_dir}")

if __name__ == "__main__":
    main()
