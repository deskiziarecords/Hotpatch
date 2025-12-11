# Runtime Verifier

This document describes the constant-time runtime checker (red-layer) and how to build/test it.

## Quickstart (local)

```bash
# build C verifier (cmake based project)
mkdir -p build && cd build
cmake ..
make c_checker
# generate a test cert (tools/cert_gen.py)
python3 ../tools/cert_gen.py test_cert.bin
# run the C checker
./c_checker ../test_cert.bin
