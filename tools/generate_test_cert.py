#!/usr/bin/env python3
# tools/generate_test_cert.py
# Creates a valid test_cert.bin for manual testing.
import hashlib
import hmac
import sys
def make_cert(path="test_cert.bin"):
    cert = bytearray(512)
    # zeros key_id
    # wcet at 0xB0
    cert[0xB0:0xB0+8] = (150000).to_bytes(8,'big')
    cert[0xB8:0xB8+8] = (1000).to_bytes(8,'big')
    cert[0xC0] = 5
    cert[0xC1] = 50   # leakage_attestation
    cert[0xC2:0xC2+8] = (1).to_bytes(8,'big')   # epoch
    # MAC under the test key bytes(range(32)); see tests/diff_test.sh
    cert[0x1E0:0x200] = hmac.new(bytes(range(32)), bytes(cert[:0x1E0]), hashlib.sha256).digest()
    with open(path,'wb') as f:
        f.write(cert)
    print("wrote", path)

if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv)>1 else "test_cert.bin"
    make_cert(p)
