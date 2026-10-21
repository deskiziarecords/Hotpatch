#!/bin/bash
set -e

# Compile C verifier
gcc -O2 -Wall src/runtime/firmware_verifier.c src/runtime/verify_cert.c -o firmware_verifier

HAVE_OCAML=0
if command -v ocamlc &> /dev/null; then
    HAVE_OCAML=1
    ocamlc -o ocaml_verifier ocaml/verifier.ml
else
    echo "ocamlc not found: OCaml differential comparison SKIPPED; checking C against expected results only."
fi

# Create test certs
mkdir -p test_certs

cat <<EOF > gen_test.py
import sys
cert = bytearray(512)
wcet = int(sys.argv[2])
budget = int(sys.argv[3])
agents = int(sys.argv[4])
leakage = int(sys.argv[5])
epoch = int(sys.argv[6])
cert[0xB0:0xB0+8] = wcet.to_bytes(8, 'big')
cert[0xB8:0xB8+8] = budget.to_bytes(8, 'big')
cert[0xC0] = agents
cert[0xC1] = leakage
cert[0xC2:0xC2+8] = epoch.to_bytes(8, 'big')
with open(sys.argv[1], 'wb') as f:
    f.write(cert)
EOF

# run_test <expected: VERIFIED|REJECTED> <cert> <key_id> <max_wcet> <max_budget> <max_agents> <max_leakage> <last_epoch>
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
U64_MAX=18446744073709551615

# Ceilings
python3 gen_test.py test_certs/t1.bin 100000 5000 5 50 2
run_test VERIFIED test_certs/t1.bin $ZERO_HASH 150000 10000 10 100 1

python3 gen_test.py test_certs/t2.bin 200000 5000 5 50 2
run_test REJECTED test_certs/t2.bin $ZERO_HASH 150000 10000 10 100 1

python3 gen_test.py test_certs/t3.bin 100000 15000 5 50 2
run_test REJECTED test_certs/t3.bin $ZERO_HASH 150000 10000 10 100 1

python3 gen_test.py test_certs/t4.bin 100000 5000 15 50 2
run_test REJECTED test_certs/t4.bin $ZERO_HASH 150000 10000 10 100 1

python3 gen_test.py test_certs/t5.bin 100000 5000 5 150 2
run_test REJECTED test_certs/t5.bin $ZERO_HASH 150000 10000 10 100 1

# Replay: epoch equal to last accepted
python3 gen_test.py test_certs/t6.bin 100000 5000 5 50 7
run_test REJECTED test_certs/t6.bin $ZERO_HASH 150000 10000 10 100 7

# Downgrade: older epoch with larger leakage value
python3 gen_test.py test_certs/t7.bin 100000 5000 5 90 3
run_test REJECTED test_certs/t7.bin $ZERO_HASH 150000 10000 10 100 7

# Epoch at u64 max (unsigned comparison)
python3 gen_test.py test_certs/t8.bin 100000 5000 5 50 $U64_MAX
run_test VERIFIED test_certs/t8.bin $ZERO_HASH 150000 10000 10 100 7
run_test REJECTED test_certs/t8.bin $ZERO_HASH 150000 10000 10 100 $U64_MAX

# WCET with the high bit set (signed comparison would wrongly accept)
python3 gen_test.py test_certs/t9.bin 9223372036854775808 5000 5 50 2
run_test REJECTED test_certs/t9.bin $ZERO_HASH 150000 10000 10 100 1

# key_id mismatch
run_test REJECTED test_certs/t1.bin 0100000000000000000000000000000000000000000000000000000000000000 150000 10000 10 100 1

if [ $HAVE_OCAML -eq 1 ]; then
    echo "All differential tests passed!"
else
    echo "All C expected-result tests passed (OCaml comparison skipped)."
fi
rm -f gen_test.py c_output.txt ocaml_output.txt firmware_verifier firmware_verifier.exe
rm -f ocaml_verifier ocaml_verifier.exe ocaml/verifier.cmi ocaml/verifier.cmo
rm -rf test_certs
