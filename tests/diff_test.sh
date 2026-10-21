#!/bin/bash
set -e

# Python with the `cryptography` package (signs test certs)
PYTHON=${PYTHON:-python3}
export PYTHONDONTWRITEBYTECODE=1

# Compile C verifier and the reference root-of-trust (libsodium)
gcc -O2 -Wall src/runtime/firmware_verifier.c src/runtime/verify_cert.c src/runtime/sha256.c -o firmware_verifier
gcc -O2 -Wall src/rot/rot_cli.c src/rot/rot_attest.c -lsodium -o rot_attest

HAVE_OCAML=0
if command -v ocamlc &> /dev/null; then
    HAVE_OCAML=1
    ocamlc -o ocaml_verifier ocaml/verifier.ml
else
    echo "ocamlc not found: OCaml differential comparison SKIPPED; checking C against expected results only."
fi

# Test-only Ed25519 seeds (private keys)
SEED="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
OTHER_SEED="ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

# Create test certs
mkdir -p test_certs

# Builds a cert and signs it with tools/sign_cert.py (Python `cryptography`).
# The signature is then checked by libsodium in rot_attest, and the digest by
# src/runtime/sha256.c and the OCaml SHA-256: three independent implementations.
cat <<EOF > gen_test.py
import sys
sys.path.insert(0, "tools")
from sign_cert import load_key, sign
cert = bytearray(512)
wcet = int(sys.argv[2])
budget = int(sys.argv[3])
agents = int(sys.argv[4])
leakage = int(sys.argv[5])
epoch = int(sys.argv[6])
mode = sys.argv[7] if len(sys.argv) > 7 else "sign"
cert[0xB0:0xB0+8] = wcet.to_bytes(8, 'big')
cert[0xB8:0xB8+8] = budget.to_bytes(8, 'big')
cert[0xC0] = agents
cert[0xC1] = leakage
cert[0xC2:0xC2+8] = epoch.to_bytes(8, 'big')
if mode != "none":
    cert = sign(cert, load_key("$SEED"))
if mode == "flip":
    cert[0x1C0] ^= 1
if mode == "tamper":
    cert[0xC1] = 0  # change the body after signing
with open(sys.argv[1], 'wb') as f:
    f.write(cert)
EOF

# attest <cert> [pubkey]: prints the RoT's latched digest, or "none" if refused
attest() {
    local OUT
    if OUT=$(./rot_attest "$1" "${2:-$PUBKEY}"); then
        echo "$OUT"
    else
        echo none
    fi
}

# run_test <expected: VERIFIED|REJECTED> <cert> <key_id> <max_wcet> <max_budget> <max_agents> <max_leakage> <stored_epoch> <attested_digest|none>
run_test() {
    local EXPECTED=$1
    shift
    local CERT=$1

    echo "Running test on $CERT (expect $EXPECTED)..."
    set +e
    ./firmware_verifier "$@" > c_output.txt
    C_EXIT=$?
    set -e

    C_OUT=$(cat c_output.txt)
    if [ "$C_OUT" != "$EXPECTED" ]; then
        echo "UNEXPECTED RESULT for $CERT: C says $C_OUT, expected $EXPECTED"
        exit 1
    fi

    if [ $HAVE_OCAML -eq 1 ]; then
        set +e
        ./ocaml_verifier "$@" > ocaml_output.txt
        OCAML_EXIT=$?
        set -e

        if [ $C_EXIT -ne $OCAML_EXIT ]; then
            echo "DIFFERENCE DETECTED for $CERT"
            echo "C exit: $C_EXIT"
            echo "OCaml exit: $OCAML_EXIT"
            exit 1
        fi

        OCAML_OUT=$(cat ocaml_output.txt)
        if [ "$C_OUT" != "$OCAML_OUT" ]; then
            echo "OUTPUT DIFFERENCE DETECTED for $CERT"
            echo "C output: $C_OUT"
            echo "OCaml output: $OCAML_OUT"
            exit 1
        fi
    fi
}

ZERO_HASH="0000000000000000000000000000000000000000000000000000000000000000"
PUBKEY=$($PYTHON tools/sign_cert.py pubkey $SEED)
OTHER_PUBKEY=$($PYTHON tools/sign_cert.py pubkey $OTHER_SEED)
U64_MAX=18446744073709551615

# Ceilings
$PYTHON gen_test.py test_certs/t1.bin 100000 5000 5 50 2
D1=$(attest test_certs/t1.bin)
run_test VERIFIED test_certs/t1.bin $ZERO_HASH 150000 10000 10 100 1 $D1

$PYTHON gen_test.py test_certs/t2.bin 200000 5000 5 50 2
run_test REJECTED test_certs/t2.bin $ZERO_HASH 150000 10000 10 100 1 $(attest test_certs/t2.bin)

$PYTHON gen_test.py test_certs/t3.bin 100000 15000 5 50 2
run_test REJECTED test_certs/t3.bin $ZERO_HASH 150000 10000 10 100 1 $(attest test_certs/t3.bin)

$PYTHON gen_test.py test_certs/t4.bin 100000 5000 15 50 2
run_test REJECTED test_certs/t4.bin $ZERO_HASH 150000 10000 10 100 1 $(attest test_certs/t4.bin)

$PYTHON gen_test.py test_certs/t5.bin 100000 5000 5 150 2
run_test REJECTED test_certs/t5.bin $ZERO_HASH 150000 10000 10 100 1 $(attest test_certs/t5.bin)

# Replay: epoch equal to the stored epoch
$PYTHON gen_test.py test_certs/t6.bin 100000 5000 5 50 7
run_test REJECTED test_certs/t6.bin $ZERO_HASH 150000 10000 10 100 7 $(attest test_certs/t6.bin)

# Downgrade: older epoch with larger leakage value
$PYTHON gen_test.py test_certs/t7.bin 100000 5000 5 90 3
run_test REJECTED test_certs/t7.bin $ZERO_HASH 150000 10000 10 100 7 $(attest test_certs/t7.bin)

# Epoch at u64 max (unsigned comparison)
$PYTHON gen_test.py test_certs/t8.bin 100000 5000 5 50 $U64_MAX
D8=$(attest test_certs/t8.bin)
run_test VERIFIED test_certs/t8.bin $ZERO_HASH 150000 10000 10 100 7 $D8
run_test REJECTED test_certs/t8.bin $ZERO_HASH 150000 10000 10 100 $U64_MAX $D8

# WCET with the high bit set (signed comparison would wrongly accept)
$PYTHON gen_test.py test_certs/t9.bin 9223372036854775808 5000 5 50 2
run_test REJECTED test_certs/t9.bin $ZERO_HASH 150000 10000 10 100 1 $(attest test_certs/t9.bin)

# key_id mismatch
run_test REJECTED test_certs/t1.bin 0100000000000000000000000000000000000000000000000000000000000000 150000 10000 10 100 1 $D1

# Authentication
# Forged brick attempt: epoch u64 max, unsigned; the RoT must refuse it
$PYTHON gen_test.py test_certs/t10.bin 100000 5000 5 50 $U64_MAX none
D10=$(attest test_certs/t10.bin)
[ "$D10" = none ] || { echo "RoT attested an unsigned cert"; exit 1; }
run_test REJECTED test_certs/t10.bin $ZERO_HASH 150000 10000 10 100 1 $D10

# One signature bit flipped
$PYTHON gen_test.py test_certs/t11.bin 100000 5000 5 50 2 flip
D11=$(attest test_certs/t11.bin)
[ "$D11" = none ] || { echo "RoT attested a flipped signature"; exit 1; }
run_test REJECTED test_certs/t11.bin $ZERO_HASH 150000 10000 10 100 1 $D11

# Body changed after signing
$PYTHON gen_test.py test_certs/t12.bin 100000 5000 5 50 2 tamper
D12=$(attest test_certs/t12.bin)
[ "$D12" = none ] || { echo "RoT attested a tampered body"; exit 1; }
run_test REJECTED test_certs/t12.bin $ZERO_HASH 150000 10000 10 100 1 $D12

# Valid cert, RoT holds a different public key
D_OTHER=$(attest test_certs/t1.bin $OTHER_PUBKEY)
[ "$D_OTHER" = none ] || { echo "RoT attested under the wrong public key"; exit 1; }
run_test REJECTED test_certs/t1.bin $ZERO_HASH 150000 10000 10 100 1 $D_OTHER

# Cert swapped after attestation: latch holds t1's digest, t8 is presented
run_test REJECTED test_certs/t8.bin $ZERO_HASH 150000 10000 10 100 1 $D1

if [ $HAVE_OCAML -eq 1 ]; then
    echo "All differential tests passed!"
else
    echo "All C expected-result tests passed (OCaml comparison skipped)."
fi
rm -f gen_test.py c_output.txt ocaml_output.txt firmware_verifier firmware_verifier.exe rot_attest rot_attest.exe
rm -f ocaml_verifier ocaml_verifier.exe ocaml/verifier.cmi ocaml/verifier.cmo
rm -rf test_certs
