#!/usr/bin/env python3
# tools/generate_test_cert.py
# Creates a valid test_cert.bin for manual testing.
import sys
def make_cert(path="test_cert.bin"):
    cert = bytearray(512)
    # zeros pubhash
    # wcet at 0xB0
    cert[0xB0:0xB0+8] = (150000).to_bytes(8,'big')
    cert[0xB8:0xB8+8] = (1000).to_bytes(8,'big')
    cert[0xC0] = 5
    with open(path,'wb') as f:
        f.write(cert)
    print("wrote", path)

if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv)>1 else "test_cert.bin"
    make_cert(p)
