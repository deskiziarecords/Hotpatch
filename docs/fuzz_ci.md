# Fuzzing & CI

`.github/workflows/ci.yml` runs on every pull request and on pushes to `main`:

| Job | What it checks |
|-----|----------------|
| **unit** | `make test` with `-Wall -Wextra -Werror`, on gcc and clang, each with and without ASan+UBSan |
| **differential** | `tests/diff_test.sh` with OCaml installed; fails if the C/OCaml comparison is skipped |
| **fuzz** | libFuzzer + ASan + UBSan on `fuzz/libfuzzer_harness.c` for 60 s, seeded by `tools/gen_corpus.py` |

Crash inputs from the fuzz job are uploaded as the `fuzz-artifacts` artifact.

## Running the fuzzer locally

```bash
clang -g -O1 -fsanitize=fuzzer,address,undefined \
      fuzz/libfuzzer_harness.c src/runtime/verify_cert.c src/runtime/hmac_sha256.c -o fuzz_target
python3 tools/gen_corpus.py
./fuzz_target -max_len=521 fuzz_corpus
```

Input format: the 512-byte certificate, then up to 8 bytes of stored epoch (big-endian), then one flag byte. If the flag's low bit is set, the harness re-signs the certificate with the test key, so mutations also reach the checks after the MAC; otherwise almost every input is rejected at the MAC step.

The harness drives `hp_accept_cert` and traps if the counter moves on a rejected certificate or fails to move forward on an accepted one.
