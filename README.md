# Hotpatch Verified Runtime  
_A constant-time, bounded-time verifier for firmware hot-patch certificates._

---

## Overview

**Hotpatch Verified Runtime** is a minimal firmware verification layer designed for safety-critical or alignment-sensitive systems.  
It checks **512-byte hot-patch certificates** against fixed ceilings, using:

- formally specified constraints  
- constant-time, bounded-time execution  
- a stratified verification architecture (ℳ₁–ℳ₄)  
- deterministic runtime monitors  
- offline heavy proofs and leakage tests  

All expensive verification steps (formal logic, leakage analysis, model proofs, Coq kernel validation, governance attestations) run **offline** and are encoded as small constants inside the certificate.  
The runtime checker performs only:

1. **MAC check**: HMAC-SHA256 over the whole certificate, through the platform's MAC hook (see [Trust Anchor](#trust-anchor))  
2. **key_id check** against the anchor  
3. **constant-time bound checks** against the anchor's ceilings (WCET / budget / agents / leakage attestation)  
4. **epoch check** against the platform's monotonic counter (replay / downgrade)  
5. **invariant preservation**  
6. **provenance validation**  

---

## Key Properties

### 1. **Bounded, Constant-Time Hot Path**  
The verifier source is written without dynamic allocation, without recursion, and without data-dependent branching.  
This is a property of the source. Constant-time is a property of the *binary on a given microarchitecture*; see [Timing Claims](#timing-claims) for what has and has not been verified.

### 2. **Stratified Verification Architecture (ℳ₁–ℳ₄)**  
Base axioms: standard ZFC. No component of a 512-byte check requires anything beyond it.

| Level | Role |
|-------|------|
| **ℳ₁** | Program logic (affine separation + constant-time types) |
| **ℳ₂** | Meta-checker (Coq kernel fragment) |
| **ℳ₃** | Governance layer (multi-sig, stakeholder votes) |
| **ℳ₄** | Side-channel & empirical leakage model |

The stratification is an engineering separation: each level checks the artifacts of the level below and is never used to certify itself.

### 3. **Two-Layer Verification Pipeline**
- **Offline:** heavy proofs, leakage tests, normative approvals  
- **Runtime:** constant-time field comparisons and invariant verification

### 4. **Fully Sandboxable**
Non-critical modules (e.g., model experiments, UIs, architectures) must run in a sandbox (e.g., RISC-V PMP).

### 5. **Leakage Attestation (`leakage_attestation`, byte `0xC1`)**
TVLA, MASCOT (mutual information) and DL-based side-channel tests are **empirical**. They run offline; their test vectors and results are attached to the certificate's provenance record.

At runtime the verifier compares the *declared* `leakage_attestation` value against a *declared* ceiling. This is a **governance attestation** — "the approved process ran and reported at most this value" — not a cryptographic leakage bound. Its assurance is exactly that of the offline tests and the vectors attached to them.

---

## Trust Anchor

A hash comparison only proves integrity if the reference value lives somewhere the agent being patched **cannot write**. A value in a register, RAM, or a writable flash page has no authority; the wiring does.

Nothing security-relevant is a caller argument. `hp_anchor_t` (`src/runtime/verify_cert.h`) carries the identity, the ceilings, and three platform hooks:

| Hook | Must be backed by |
|------|-------------------|
| `mac` | HMAC-SHA256 under a key the agent cannot read: a hardware engine with a sealed key |
| `read_epoch` / `advance_epoch` | Monotonic storage the verified agent cannot rewrite: write-once/monotonic NVRAM, OTP counter, RPMB, or a register only the root-of-trust can write. The storage itself must refuse non-increasing values |

The platform must place the anchor itself in storage the agent cannot write (OTP, ROM, or memory locked by the root-of-trust). The verifier cannot check any of these placements; it only reads through the anchor. If the counter can be rewritten by software, replay protection is only a suggestion. If the agent can read the MAC key, it can forge certificates.

**API.**
- `verify_cert(cert, anchor)` is a pure check with no side effects.
- `hp_accept_cert(cert, anchor)` is the **only** path that advances the counter: it authenticates first, then advances. Apply a patch only if it returns 1.

**Order matters.** Advancing the counter before authenticating would let a forged certificate with `epoch = 2⁶⁴−1` push the counter to the maximum and permanently refuse every future update: a self-inflicted brick, with no memory exploit and no timing attack. The counter is only advanced after the MAC check passes, always.

**Software reference.** `src/runtime/hmac_sha256.c` is a software HMAC-SHA256, tested against the FIPS 180-4 and RFC 4231 vectors and cross-checked against the OCaml reference and Python's `hmac`. Tests, CI and the CLI harness use it with the fixed test key `00 01 … 1f`. A key held in software is readable by anything that shares its address space, so on a device the `mac` hook should be a hardware engine.

**Alternative: off-path signature.** If the platform has no sealed key block, verify an Ed25519 (or similar) signature in a separate root-of-trust before the certificate reaches the bounded path, and have the `mac` hook check the result in an unwritable latch. Ed25519 is not trivially constant-time and must **not** be placed inside the bounded hot path without its own timing analysis.

---

## Timing Claims

The `150000` that appears in tests is the **ceiling for the patch's declared WCET** (field `0xB0`), not a measured bound on the verifier itself.

A verifier WCET bound must be stated in this form before it is claimed:

> ≤ _X_ µs on _[CPU model, frequency]_, over _N_ certificates, WCET determined by _[tool or measurement method]_, compiler _[name, version, flags]_, no dynamic allocation, no recursion, no data-dependent branching.

**Status:** not yet measured. No figure is claimed.

Constant-time must be verified on the binary, because the compiler can reintroduce branches or variable-time instructions:

- **ct-verif** (or equivalent) on the compiled binary — formal evidence  
- **dudect / ctgrind** — empirical evidence  

**Status:** neither has been run yet.

---

## Repository Structure
```plaintext
/
├── src/
│   └── runtime/          # Constant-time C verifier (Red layer)
│
├── c/                    # C integration & wrappers
├── ocaml/                # ℳ₂ meta-checker prototype  
├── coq/                  # ℳ₁/ℳ₂ Coq specifications (placeholder)
│
├── fuzz/                 # LibFuzzer harness + corpus
├── tools/                # Corpus generator, triage, analysis tools
│
├── tests/                # Unit, integration, and differential tests
└── .github/workflows     # CI fuzzing + differential checking

```

---

## Building

### **C Runtime**
```bash
mkdir build && cd build
cmake ..
make
```
---

## OCaml Meta-Checker
```bash
cd ocaml
dune build
```
## Fuzzing (libFuzzer)

Requires Clang:

```bash
cmake -DFUZZ=ON ..
make fuzz_target
./fuzz_target

```
## Security Model
### Threats Addressed

- malformed certificates
- adversarial bit-patterns
- timing attacks on equality checks
- misaligned or unbounded parsing
- unapproved normative changes
- unvetted leakage-attestation values
- side-channel leakage inconsistencies
- rollback state corruption

### Replay and Downgrade Invariants

A fixed-size certificate has two obvious attacks. Both are checked in the constant-time path:

- **Replay.** The certificate carries a monotonic `epoch` (u64, offset `0xC2`). It is accepted only if `epoch > anchor->read_epoch()`. On accept, `hp_accept_cert` advances the counter to the certificate's epoch; apply the patch only after that succeeds.
- **Downgrade.** An older certificate with a larger `leakage_attestation` (or larger budget / WCET) is rejected by the same epoch check. Ceilings come from the anchor, not from the caller, so a newer certificate cannot exceed them either.
- **Counter exhaustion (brick).** The epoch is covered by the MAC and the counter only moves after the MAC check, so a forged `epoch = 2⁶⁴−1` cannot reach the counter.

All three hold only if the counter, the anchor and the MAC key are truly out of the agent's reach (see [Trust Anchor](#trust-anchor)). A *legitimately signed* certificate with `epoch = 2⁶⁴−1` still exhausts the counter; the offline signing process must not issue one.

### Certificate Layout

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `key_id` | 32 bytes |
| `0xB0` | `wcet_ns` (declared, of the patch) | u64 BE |
| `0xB8` | `budget` (ΔB) | u64 BE |
| `0xC0` | `agents` | u8 |
| `0xC1` | `leakage_attestation` | u8 |
| `0xC2` | `epoch` | u64 BE |
| `0x1E0` | `mac`: HMAC-SHA256 over bytes `0x000..0x1DF` | 32 bytes |

### Threats Explicitly Not Addressed

- microarchitectural leakage beyond the ℳ₄ model
- hardware trojans
- undefined governance processes outside ℳ₃
- undefined behavior in sandboxed “yellow” modules

## Governance & Normative Layer (ℳ₃)

All normative decisions (safety weights, acceptable leakage-attestation ceiling, budget ceilings, and permissible model classes) are stored as:

- multi-sig validated transactions
- stake-weighted votes
- immutable merkle-root logs
- hash-linked provenance references inside every 512-byte cert

The runtime checker enforces these decisions deterministically, **only to the extent that they are bound to the trust anchor** described above.

## Contributing

### This is a high-assurance project.
All contributions must:

- preserve constant-time properties (verified on the binary, not only the source)
- avoid data-dependent branching
- compile without warnings under -Wall -Wextra -Werror
- include unit tests
- include fuzz seeds for new parsers
- pass differential testing against the OCaml reference checker

Formal adjustments (Coq) must preserve soundness in ℳ₁/ℳ₂ and be accompanied by a written design note.

## Credits
Author: J. Roberto Jiménez 
