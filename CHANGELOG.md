# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No versions have been tagged yet.

## [Unreleased]

### Security
- Certificates are authenticated: HMAC-SHA256 over bytes `0x000..0x1DF`, stored at `0x1E0`, computed by the platform's `mac` hook (a hardware engine with a sealed key on a device) and compared in constant time. ([#4])
- Certificates carry a monotonic `epoch` (u64 BE, offset `0xC2`) and are accepted only if `epoch` exceeds the platform's stored counter, checked in constant time. This blocks replay (same epoch) and downgrade to older certificates (e.g. one with a larger leakage value). ([#2], [#4])
- Nothing security-relevant is a caller argument: `key_id`, ceilings, the epoch counter (`read_epoch` / `advance_epoch`) and the MAC come from a provisioned trust anchor (`hp_anchor_t`). ([#2], [#4])
- `hp_accept_cert()` is the only path that advances the counter, and only after the MAC check passes, so a forged certificate with `epoch = 2⁶⁴−1` cannot exhaust the counter and brick future updates. ([#4])

### Changed
- **Breaking:** `verify_cert(cert, expected_pubhash, max_wcet_ns, max_budget, max_agents, max_epsilon)` is now `verify_cert(cert, anchor)`, a pure check; `hp_accept_cert(cert, anchor)` verifies and advances the counter. ([#2], [#4])
- **Breaking:** the certificate format adds `epoch` at `0xC2` and `mac` at `0x1E0`. ([#2], [#4])
- `firmware_verifier` and the OCaml reference checker take `<key_id_hex> <max_wcet_ns> <max_budget> <max_agents> <max_leakage> <stored_epoch> <mac_key_hex>`. ([#2], [#4])
- `epsilon` renamed to `leakage_attestation`. It is a governance attestation of offline empirical tests (TVLA, MASCOT, DL), not a cryptographic bound. ([#2])
- README: removed the "ZFC + inaccessibles" level (ℳ₀) and the Gödel/Löb claim; added *Trust Anchor*, *Timing Claims* and *Certificate Layout* sections. The `150000` used in tests is documented as the ceiling on the patch's declared WCET, not a measured bound on the verifier. ([#2], [#4])

### Added
- `src/runtime/hmac_sha256.{c,h}`: software HMAC-SHA256 reference for tests and CI, checked against FIPS 180-4 and RFC 4231 vectors. An independent SHA-256/HMAC in the OCaml reference, and Python's `hmac` in the differential test, cross-check it. ([#4])
- Unit tests for replay, downgrade, MAC tampering, the forged-epoch brick attempt, storage failure on advance, and `UINT64_MAX` / high-bit edge cases. ([#2], [#4])
- Fuzz harness drives `hp_accept_cert`, reads the stored epoch from bytes after offset 512, can re-sign inputs so mutations reach the post-MAC checks, and traps if the counter moves on a rejected certificate. New epoch and forged-MAC seeds in the corpus. ([#2], [#4])
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
