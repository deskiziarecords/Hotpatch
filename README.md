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

1. **attestation check**: SHA-256 of the whole certificate, compared in constant time with the digest the root-of-trust latched after verifying the Ed25519 signature off-path (see [Trust Anchor](#trust-anchor))  
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

**Authentication is off-path, and the device holds no secret.**

| Step | Where | What it does |
|------|-------|--------------|
| Sign | Offline (`tools/sign_cert.py`; an HSM in production) | Ed25519 over bytes `0x000..0x1BF`; signature at `0x1C0..0x1FF` |
| Attest | Root-of-trust, off the bounded path (`src/rot/rot_attest.c`, reference using libsodium) | Verifies the signature with the public key held in its OTP. On success, latches SHA-256 of all 512 bytes in a register only it can write; on failure, clears the latch |
| Verify | Bounded path (`verify_cert`) | Hashes the 512 bytes and compares with the latch in constant time |

The bounded path runs no Ed25519 (which is not trivially constant-time) and holds no key, so there is nothing on the device to steal: an agent that can read everything still cannot forge a certificate. Because the digest covers the exact 512 bytes the root-of-trust checked, swapping or editing the buffer after attestation (TOCTOU) is rejected.

Nothing security-relevant is a caller argument. `hp_anchor_t` (`src/runtime/verify_cert.h`) carries the identity, the ceilings, and the platform hooks:

| Hook | Must be backed by |
|------|-------------------|
| `read_attestation` | The root-of-trust's latch: readable by the verifier, writable only by the root-of-trust |
| `read_epoch` / `advance_epoch` | Monotonic storage the verified agent cannot rewrite: write-once/monotonic NVRAM, OTP counter, RPMB, or a register only the root-of-trust can write. The storage itself must refuse non-increasing values |

The platform must place the anchor itself in storage the agent cannot write (OTP, ROM, or memory locked by the root-of-trust). The verifier cannot check any of these placements; it only reads through the anchor. If the counter can be rewritten by software, replay protection is only a suggestion. If the agent can write the latch, it can make the verifier accept anything.

**API.**
- `verify_cert(cert, anchor)` is a pure check with no side effects.
- `hp_accept_cert(cert, anchor)` is the **only** path that advances the counter: it checks the attestation first, then advances. Apply a patch only if it returns 1.

**Order matters.** Advancing the counter before authenticating would let a forged certificate with `epoch = 2⁶⁴−1` push the counter to the maximum and permanently refuse every future update: a self-inflicted brick, with no memory exploit and no timing attack. The root-of-trust never attests a forged certificate, and the counter only moves after the attestation check passes, always.

**Evidence.** Three independent implementations must agree end to end: Python `cryptography` signs, libsodium verifies the signature and computes the latched SHA-256, and `src/runtime/sha256.c` (FIPS 180-4 vectors) and the OCaml reference recompute it. `tests/test_rot.c` also checks libsodium against the RFC 8032 Ed25519 vector. Tests use the fixed seed `00 01 … 1f`; it is not a key.

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
- **Counter exhaustion (brick).** The epoch is covered by the signature, the root-of-trust never attests a forged certificate, and the counter only moves after the attestation check, so a forged `epoch = 2⁶⁴−1` cannot reach the counter.

All three hold only if the counter, the anchor and the attestation latch are truly out of the agent's reach (see [Trust Anchor](#trust-anchor)). A *legitimately signed* certificate with `epoch = 2⁶⁴−1` still exhausts the counter; the offline signing process must not issue one.

### Certificate Layout

| Offset | Field | Type |
|--------|-------|------|
| `0x00` | `key_id` | 32 bytes |
| `0xB0` | `wcet_ns` (declared, of the patch) | u64 BE |
| `0xB8` | `budget` (ΔB) | u64 BE |
| `0xC0` | `agents` | u8 |
| `0xC1` | `leakage_attestation` | u8 |
| `0xC2` | `epoch` | u64 BE |
| `0x1C0` | `signature`: Ed25519 over bytes `0x000..0x1BF` | 64 bytes |

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
