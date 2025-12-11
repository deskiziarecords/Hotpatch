# Hotpatch Verified Runtime  
_A formally principled, constant-time, safety-critical verifier for authenticated firmware hot-patches._

---

## Overview

**Hotpatch Verified Runtime** is a minimal, high-assurance firmware verification layer designed for safety-critical or alignment-sensitive systems.  
It validates **512-byte hot-patch certificates** in **≤150 µs**, using a combination of:

- formally specified constraints  
- constant-time and bounded-time execution  
- a strict expressiveness model (ℳ₀–ℳ₄)  
- deterministic runtime monitors  
- offline heavy proofs and leakage tests  

All expensive verification steps (formal logic, leakage analysis, model proofs, Coq kernel validation, governance attestations) run **offline** and are encoded as small constants inside the certificate.  
The runtime checker performs only:

1. **constant-time hash check**  
2. **constant-time bound checks** (budget / agents / epsilon)  
3. **invariant preservation**  
4. **provenance validation**  

This produces a system with **hardware-level predictability** and **auditable mathematical structure**, intended for applications where trust, correctness, and alignment cannot rely on opaque model-level behavior.

---

## Key Properties

### 1. **WCET-Bounded (≤150 µs)**  
All operations in the verifier are strictly constant-time and branch-independent.  
No dynamic allocation, no variable-time parsing, no recursion.

### 2. **Stratified Formal Architecture (ℳ₀–ℳ₄)**  
The system follows a layered meta-logic model:

| Level | Role |
|-------|------|
| **ℳ₀** | Base axioms (ZFC + inaccessibles) |
| **ℳ₁** | Program logic (affine separation + constant-time types) |
| **ℳ₂** | Meta-checker (Coq kernel fragment) |
| **ℳ₃** | Governance layer (multi-sig, stakeholder votes) |
| **ℳ₄** | Side-channel & empirical leakage model |

This prevents self-reference and avoids Gödel/Löb pitfalls.

### 3. **Two-Layer Verification Pipeline**
- **Offline:** heavy proofs, leakage tests, normative approvals  
- **Runtime:** constant-time field comparisons and invariant verification

### 4. **Fully Sandboxable**
Non-critical modules (e.g., model experiments, UIs, architectures) must run in a sandbox (e.g., RISC-V PMP).

### 5. **Empirical Leakage Model**
Certificates include hashed results of:

- TVLA  
- MASCOT (mutual information)  
- DL-based side-channel resilience tests  

Runtime only checks the *declared* ε-bound, not statistics.

## **Repository Structure**
```plaintext
/
├── src/
│   └── runtime/          # Constant-time C verifier (Red layer)
│
├── c/                    # C integration & wrappers
├── ocaml/                # ℳ₂ meta-checker prototype  
├── coq/                  # ℳ₁/ℳ₂ Coq specifications
│
├── fuzz/                 # LibFuzzer harness + corpus
├── tools/                # Corpus generator, triage, analysis tools
│
├── test/                 # Unit, integration, and golden tests
└── .github/workflows     # CI fuzzing + differential checking

```
This structure mirrors open-source high-assurance systems (seL4, CompCert, OpenTitan).

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

malformed certificates

adversarial bit-patterns

timing attacks on equality checks

misaligned or unbounded parsing

unapproved normative changes

unvetted ε-parameters

side-channel leakage inconsistencies

rollback state corruption

### Threats Explicitly Not Addressed

microarchitectural leakage beyond ℳ₄ model

hardware trojans

undefined governance processes outside ℳ₃

undefined behavior in sandboxed “yellow” modules

Clear threat boundaries improve audit clarity.

## Governance & Normative Layer (ℳ₃)

All normative decisions (safety weights, acceptable ε, budget ceilings, and permissible model classes) are stored as:

multi-sig validated transactions

stake-weighted votes

immutable merkle-root logs

hash-linked provenance references inside every 512-byte cert

The runtime checker enforces these decisions deterministically.

## Contributing

### This is a high-assurance project.
All contributions must:

preserve constant-time properties

avoid data-dependent branching

compile without warnings under -Wall -Wextra -Werror

include unit tests

include fuzz seeds for new parsers

pass differential testing against the OCaml reference checker

Formal adjustments (Coq) must preserve soundness in ℳ₁/ℳ₂ and be accompanied by a written design note.

## Credits
Author: J. Roberto Jiménez 
