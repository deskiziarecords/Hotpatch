#!/bin/bash
set -e

# Compile C verifier
gcc -O2 -Wall src/runtime/firmware_verifier.c src/runtime/verify_cert.c src/runtime/hmac_sha256.c -o firmware_verifier

HAVE_OCAML=0
if command -v ocamlc &> /dev/null; then
    HAVE_OCAML=1
    ocamlc -o ocaml_verifier ocaml/verifier.ml
else
    echo "ocamlc not found: OCaml differential comparison SKIPPED; checking C against expected results only."
fi

# Create test certs
mkdir -p test_certs

# Certs are signed with Python's hmac module: a third implementation that the
# C and OCaml HMAC-SHA256 must both agree with.
cat <<EOF > gen_test.py
import sys, hmac, hashlib
cert = bytearray(512)
wcet = int(sys.argv[2])
budget = int(sys.argv[3])
agents = int(sys.argv[4])
leakage = int(sys.argv[5])
epoch = int(sys.argv[6])
mac_mode = sys.argv[7] if len(sys.argv) > 7 else "sign"
cert[0xB0:0xB0+8] = wcet.to_bytes(8, 'big')
cert[0xB8:0xB8+8] = budget.to_bytes(8, 'big')
cert[0xC0] = agents
cert[0xC1] = leakage
cert[0xC2:0xC2+8] = epoch.to_bytes(8, 'big')
key = bytes(range(32))
if mac_mode in ("sign", "flip"):
    cert[0x1E0:0x200] = hmac.new(key, bytes(cert[:0x1E0]), hashlib.sha256).digest()
if mac_mode == "flip":
    cert[0x1E0] ^= 1
with open(sys.argv[1], 'wb') as f:
    f.write(cert)
EOF

# run_test <expected: VERIFIED|REJECTED> <cert> <key_id> <max_wcet> <max_budget> <max_agents> <max_leakage> <stored_epoch> <mac_key>
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
MAC_KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
WRONG_KEY="ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
U64_MAX=18446744073709551615

# Ceilings
python3 gen_test.py test_certs/t1.bin 100000 5000 5 50 2
run_test VERIFIED test_certs/t1.bin $ZERO_HASH 150000 10000 10 100 1 $MAC_KEY

python3 gen_test.py test_certs/t2.bin 200000 5000 5 50 2
run_test REJECTED test_certs/t2.bin $ZERO_HASH 150000 10000 10 100 1 $MAC_KEY

python3 gen_test.py test_certs/t3.bin 100000 15000 5 50 2
run_test REJECTED test_certs/t3.bin $ZERO_HASH 150000 10000 10 100 1 $MAC_KEY

python3 gen_test.py test_certs/t4.bin 100000 5000 15 50 2
run_test REJECTED test_certs/t4.bin $ZERO_HASH 150000 10000 10 100 1 $MAC_KEY

python3 gen_test.py test_certs/t5.bin 100000 5000 5 150 2
run_test REJECTED test_certs/t5.bin $ZERO_HASH 150000 10000 10 100 1 $MAC_KEY

# Replay: epoch equal to the stored epoch
python3 gen_test.py test_certs/t6.bin 100000 5000 5 50 7
run_test REJECTED test_certs/t6.bin $ZERO_HASH 150000 10000 10 100 7 $MAC_KEY

# Downgrade: older epoch with larger leakage value
python3 gen_test.py test_certs/t7.bin 100000 5000 5 90 3
run_test REJECTED test_certs/t7.bin $ZERO_HASH 150000 10000 10 100 7 $MAC_KEY

# Epoch at u64 max (unsigned comparison)
python3 gen_test.py test_certs/t8.bin 100000 5000 5 50 $U64_MAX
run_test VERIFIED test_certs/t8.bin $ZERO_HASH 150000 10000 10 100 7 $MAC_KEY
run_test REJECTED test_certs/t8.bin $ZERO_HASH 150000 10000 10 100 $U64_MAX $MAC_KEY

# WCET with the high bit set (signed comparison would wrongly accept)
python3 gen_test.py test_certs/t9.bin 9223372036854775808 5000 5 50 2
run_test REJECTED test_certs/t9.bin $ZERO_HASH 150000 10000 10 100 1 $MAC_KEY

# key_id mismatch
run_test REJECTED test_certs/t1.bin 0100000000000000000000000000000000000000000000000000000000000000 150000 10000 10 100 1 $MAC_KEY

# Authentication
# Forged brick attempt: epoch u64 max, no MAC
python3 gen_test.py test_certs/t10.bin 100000 5000 5 50 $U64_MAX none
run_test REJECTED test_certs/t10.bin $ZERO_HASH 150000 10000 10 100 1 $MAC_KEY

# One MAC bit flipped
python3 gen_test.py test_certs/t11.bin 100000 5000 5 50 2 flip
run_test REJECTED test_certs/t11.bin $ZERO_HASH 150000 10000 10 100 1 $MAC_KEY

# Valid cert, verifier holds a different key
run_test REJECTED test_certs/t1.bin $ZERO_HASH 150000 10000 10 100 1 $WRONG_KEY

if [ $HAVE_OCAML -eq 1 ]; then
    echo "All differential tests passed!"
else
    echo "All C expected-result tests passed (OCaml comparison skipped)."
fi
rm -f gen_test.py c_output.txt ocaml_output.txt firmware_verifier firmware_verifier.exe
rm -f ocaml_verifier ocaml_verifier.exe ocaml/verifier.cmi ocaml/verifier.cmo
rm -rf test_certs
