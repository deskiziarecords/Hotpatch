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
      fuzz/libfuzzer_harness.c src/runtime/verify_cert.c -o fuzz_target
python3 tools/gen_corpus.py
./fuzz_target -max_len=520 fuzz_corpus
```

Inputs longer than 512 bytes carry `last_epoch` in the trailing bytes (big-endian, up to 8), so `-max_len=520` lets the fuzzer explore the replay boundary.
