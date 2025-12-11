# Hotpatch Verified Runtime (with verifier)
This archive contains a constant-time firmware verifier implementation (red-layer)
and a small test harness.

Files added:
- src/runtime/verify_cert.c
- src/runtime/verify_cert.h
- tests/test_verify.c
- tools/generate_test_cert.py
- Makefile

Build & test:
  make
  make test

Credits: ChatGPT (assistance and specification)
