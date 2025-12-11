# Formal Specification (ℳ₁ / ℳ₂)

This page summarizes the Coq model and the key theorems.

## What is formalized

- Byte-level certificate model (512 bytes).
- Big-endian decoding of numeric fields.
- Boolean verifier `verify_cert_bool` implemented in Coq.
- Logical predicate `verify_cert_spec`.
- Theorem: `verify_cert_bool c expected L = true <-> verify_cert_spec c expected L`.

## Where to find the files

- `coq/verifier_spec.v` — the main Coq file with the spec and proof skeletons.
- `coq/extract_verifier.v` — extraction stanza to produce OCaml.

## Extraction & trusted toolchain notes

- We extract to OCaml (or use CertiCoq → C for a pure-C binary).
- The OCaml runtime is acceptable for offline/CI checks but consider CertiCoq / CompCert for true runtime TCB.
