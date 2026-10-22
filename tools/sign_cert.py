#!/usr/bin/env python3
# tools/sign_cert.py
# Offline signer: writes an Ed25519 signature over bytes 0x000..0x1BF of a
# 512-byte certificate into 0x1C0..0x1FF. Requires the `cryptography` package.
#
#   sign_cert.py sign <cert_in> <cert_out> <seed_hex>
#   sign_cert.py pubkey <seed_hex>
#
# The seed is the Ed25519 private key. Tests use the fixed seed 00..1f; a
# real signing key belongs in an HSM, never in a file or on the command line.
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CERT_SIZE = 512
OFF_SIG = 0x1C0


def load_key(seed_hex):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


def sign(cert, key):
    cert = bytearray(cert)
    if len(cert) != CERT_SIZE:
        raise ValueError(f"certificate must be {CERT_SIZE} bytes, got {len(cert)}")
    cert[OFF_SIG:] = key.sign(bytes(cert[:OFF_SIG]))
    return cert


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "sign":
        with open(sys.argv[2], "rb") as f:
            cert = f.read()
        with open(sys.argv[3], "wb") as f:
            f.write(sign(cert, load_key(sys.argv[4])))
    elif len(sys.argv) == 3 and sys.argv[1] == "pubkey":
        pub = load_key(sys.argv[2]).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        print(pub.hex())
    else:
        print("usage: sign_cert.py sign <in> <out> <seed_hex> | pubkey <seed_hex>", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
