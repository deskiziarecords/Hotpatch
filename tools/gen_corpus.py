#!/usr/bin/env python3
import os

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

def main():
    corpus_dir = "fuzz_corpus"
    if not os.path.exists(corpus_dir):
        os.makedirs(corpus_dir)

    # Valid cert
    with open(os.path.join(corpus_dir, "valid_1"), "wb") as f:
        f.write(make_cert(100000, 5000, 5, 50))

    # Boundary certs
    with open(os.path.join(corpus_dir, "boundary_wcet"), "wb") as f:
        f.write(make_cert(150000, 5000, 5, 50))

    with open(os.path.join(corpus_dir, "boundary_budget"), "wb") as f:
        f.write(make_cert(100000, 10000, 5, 50))

    with open(os.path.join(corpus_dir, "boundary_agents"), "wb") as f:
        f.write(make_cert(100000, 5000, 10, 50))

    with open(os.path.join(corpus_dir, "boundary_leakage"), "wb") as f:
        f.write(make_cert(100000, 5000, 5, 100))

    # Invalid certs
    with open(os.path.join(corpus_dir, "invalid_wcet"), "wb") as f:
        f.write(make_cert(200000, 5000, 5, 50))

    # Replay seed: epoch 0 never exceeds last_epoch (the harness reads
    # last_epoch from bytes past offset 512; absent, it is 0)
    with open(os.path.join(corpus_dir, "replay_epoch0"), "wb") as f:
        f.write(make_cert(100000, 5000, 5, 50, epoch=0))

    # Epoch boundary: cert epoch 7, trailing last_epoch 6 (accept) and 7 (reject)
    with open(os.path.join(corpus_dir, "epoch_boundary_accept"), "wb") as f:
        f.write(make_cert(100000, 5000, 5, 50, epoch=7) + (6).to_bytes(8, 'big'))
    with open(os.path.join(corpus_dir, "epoch_boundary_replay"), "wb") as f:
        f.write(make_cert(100000, 5000, 5, 50, epoch=7) + (7).to_bytes(8, 'big'))

    print(f"Generated corpus in {corpus_dir}")

if __name__ == "__main__":
    main()
