#!/usr/bin/env python3
# tools/generate_test_cert.py
# Creates a valid, signed test_cert.bin for manual testing.
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_cert import load_key, sign

# Test-only Ed25519 seed; see tests/diff_test.sh
TEST_SEED = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

def make_cert(path="test_cert.bin"):
    cert = bytearray(512)
    # zeros key_id
    # wcet at 0xB0
    cert[0xB0:0xB0+8] = (150000).to_bytes(8,'big')
    cert[0xB8:0xB8+8] = (1000).to_bytes(8,'big')
    cert[0xC0] = 5
    cert[0xC1] = 50   # leakage_attestation
    cert[0xC2:0xC2+8] = (1).to_bytes(8,'big')   # epoch
    cert = sign(cert, load_key(TEST_SEED))
    with open(path,'wb') as f:
        f.write(cert)
    print("wrote", path)

if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv)>1 else "test_cert.bin"
    make_cert(p)
