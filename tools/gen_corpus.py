#!/usr/bin/env python3
import os

def make_cert(wcet, budget, agents, epsilon, pubhash=None):
    cert = bytearray(512)
    if pubhash:
        cert[0:32] = pubhash
    cert[0xB0:0xB0+8] = wcet.to_bytes(8, 'big')
    cert[0xB8:0xB8+8] = budget.to_bytes(8, 'big')
    cert[0xC0] = agents
    cert[0xC1] = epsilon
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

    with open(os.path.join(corpus_dir, "boundary_epsilon"), "wb") as f:
        f.write(make_cert(100000, 5000, 5, 100))

    # Invalid certs
    with open(os.path.join(corpus_dir, "invalid_wcet"), "wb") as f:
        f.write(make_cert(200000, 5000, 5, 50))

    print(f"Generated corpus in {corpus_dir}")

if __name__ == "__main__":
    main()
