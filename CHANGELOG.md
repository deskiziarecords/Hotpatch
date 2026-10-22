# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No versions have been tagged yet.

## [Unreleased]

### Security
- Certificates are authenticated off-path: an Ed25519 signature over bytes `0x000..0x1BF` (at `0x1C0`) is verified by a separate root-of-trust, which latches SHA-256 of the full certificate; the bounded verifier compares that digest in constant time. The device holds no secret key, and editing or swapping the buffer after attestation is rejected. ([#4])
- Certificates carry a monotonic `epoch` (u64 BE, offset `0xC2`) and are accepted only if `epoch` exceeds the platform's stored counter, checked in constant time. This blocks replay (same epoch) and downgrade to older certificates (e.g. one with a larger leakage value). ([#2], [#4])
- Nothing security-relevant is a caller argument: `key_id`, ceilings, the epoch counter (`read_epoch` / `advance_epoch`) and the attestation latch (`read_attestation`) come from a provisioned trust anchor (`hp_anchor_t`). ([#2], [#4])
- `hp_accept_cert()` is the only path that advances the counter, and only after the attestation check passes, so a forged certificate with `epoch = 2⁶⁴−1` cannot exhaust the counter and brick future updates. ([#4])

### Changed
- **Breaking:** `verify_cert(cert, expected_pubhash, max_wcet_ns, max_budget, max_agents, max_epsilon)` is now `verify_cert(cert, anchor)`, a pure check; `hp_accept_cert(cert, anchor)` verifies and advances the counter. ([#2], [#4])
- **Breaking:** the certificate format adds `epoch` at `0xC2` and a 64-byte Ed25519 `signature` at `0x1C0`. ([#2], [#4])
- `firmware_verifier` and the OCaml reference checker take `<key_id_hex> <max_wcet_ns> <max_budget> <max_agents> <max_leakage> <stored_epoch> <attested_digest_hex|none>`. ([#2], [#4])
- `epsilon` renamed to `leakage_attestation`. It is a governance attestation of offline empirical tests (TVLA, MASCOT, DL), not a cryptographic bound. ([#2])
- README: removed the "ZFC + inaccessibles" level (ℳ₀) and the Gödel/Löb claim; added *Trust Anchor*, *Timing Claims* and *Certificate Layout* sections. The `150000` used in tests is documented as the ceiling on the patch's declared WCET, not a measured bound on the verifier. ([#2], [#4])

### Added
- `src/rot/`: reference root-of-trust (`hp_rot_attest`, libsodium) and its CLI; `tools/sign_cert.py`: offline Ed25519 signer (Python `cryptography`). ([#4])
- `src/runtime/sha256.{c,h}`: SHA-256 for the bounded path, checked against FIPS 180-4 vectors and cross-checked against libsodium and an independent SHA-256 in the OCaml reference. ([#4])
- `tests/test_rot.c`: RFC 8032 Ed25519 vector, signature/body tampering, wrong key, and end-to-end sign → attest → `hp_accept_cert`, including a cert swapped after attestation. ([#4])
- Unit tests for replay, downgrade, attestation tampering (TOCTOU), the forged-epoch brick attempt, storage failure on advance, and `UINT64_MAX` / high-bit edge cases. ([#2], [#4])
- Fuzz harness drives `hp_accept_cert`, reads the stored epoch from bytes after offset 512, can simulate a successful attestation so mutations reach the post-attestation checks, and traps if an unattested certificate is accepted or the counter moves on a rejected one. New epoch and forged-epoch seeds in the corpus. ([#2], [#4])
- CI (`.github/workflows/ci.yml`): unit tests on gcc and clang with and without ASan+UBSan, C/OCaml differential test, 60 s libFuzzer run. ([#3])
- `docs/fuzz_ci.md`. ([#3])

### Fixed
- OCaml reference compared u64 fields as signed `Int64`, so a WCET ≥ 2⁶³ was rejected by C but accepted by OCaml. ([#2])
- `tests/diff_test.sh` read exit codes after `|| true`, so they were always 0, and without OCaml it copied C's output as OCaml's and passed. Each case now has an expected result. ([#2])
- `tests/test_verify.c` always exited 0; it now fails on any mismatch. ([#2])

## Initial prototype — 2026-03-06

### Added
- Branch-free constant-time comparisons for unsigned integers; WCET, budget, agents and epsilon bound checks on 512-byte certificates. ([#1])
- C CLI verifier (`firmware_verifier`) and OCaml reference implementation. ([#1])
- Unit tests, differential test script, libFuzzer harness and corpus generator. ([#1])

[Unreleased]: https://github.com/deskiziarecords/Hotpatch/compare/ebfcbb9...main
[#1]: https://github.com/deskiziarecords/Hotpatch/pull/1
[#2]: https://github.com/deskiziarecords/Hotpatch/pull/2
[#3]: https://github.com/deskiziarecords/Hotpatch/pull/3
[#4]: https://github.com/deskiziarecords/Hotpatch/pull/4
