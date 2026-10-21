# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No versions have been tagged yet.

## [Unreleased]

### Security
- Certificates carry a monotonic `epoch` (u64 BE, offset `0xC2`) and are accepted only if `epoch > last_epoch`, checked in constant time. This blocks replay (same epoch) and downgrade to older certificates (e.g. one with a larger leakage value). ([#2])
- Ceilings and `key_id` are read from a provisioned trust anchor (`hp_anchor_t`) instead of caller arguments. ([#2])
- **Known gap:** certificates are still not authenticated. `key_id` is compared, not verified with a MAC or signature, so anyone who knows it can forge a certificate, including one with a higher epoch.

### Changed
- **Breaking:** `verify_cert(cert, expected_pubhash, max_wcet_ns, max_budget, max_agents, max_epsilon)` is now `verify_cert(cert, anchor, last_epoch)`. ([#2])
- `firmware_verifier` and the OCaml reference checker take `<key_id_hex> <max_wcet_ns> <max_budget> <max_agents> <max_leakage> <last_epoch>`. ([#2])
- `epsilon` renamed to `leakage_attestation`. It is a governance attestation of offline empirical tests (TVLA, MASCOT, DL), not a cryptographic bound. ([#2])
- README: removed the "ZFC + inaccessibles" level (ℳ₀) and the Gödel/Löb claim; added *Trust Anchor*, *Timing Claims* and *Certificate Layout* sections. The `150000` used in tests is documented as the ceiling on the patch's declared WCET, not a measured bound on the verifier. ([#2])

### Added
- `hp_cert_epoch()` so the platform can advance its monotonic counter before applying a patch. ([#2])
- Unit tests for replay, downgrade, and `UINT64_MAX` / high-bit edge cases. ([#2])
- Fuzz harness reads `last_epoch` from bytes after offset 512; new epoch seeds in the corpus. ([#2])
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
