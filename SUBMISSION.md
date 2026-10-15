# Builder → Intelligent Contracts

## Title

BoundedPolicyCompiler — Consensus-Compiled Policy Functions

## Notes / Description

BoundedPolicyCompiler turns a commit-pinned published policy into an immutable four-valued function. Callers define an action and 1–4 Boolean predicates but cannot supply document bodies, decisions or confidence.

Leader and validators independently fetch the full source, verify HTTP status and SHA-256, enumerate all hypothetical assignments, and derive ALLOW, DENY, CONFLICT or UNKNOWN for every cell. Exact equality of the complete report is required before installing an artifact.

Root-bound reads handle partially known contexts: ALLOW or DENY is returned only when every possible completion agrees; mixed, unknown or conflicting cases remain UNRESOLVED. HELD attempts expose no artifact and do not block retries. Nonce replay and duplicate artifacts are rejected.

StudioNet proofs cover complete and uncertain compilation, bad-hash holding and rejection paths. This is hypothetical document interpretation, not real-world authorization. 43 tests pass.

## Evidence

- Repository: https://github.com/ehsandto/bounded-policy-compiler
- Contract: https://github.com/ehsandto/bounded-policy-compiler/blob/main/contracts/BoundedPolicyCompiler.py
- README: https://github.com/ehsandto/bounded-policy-compiler/blob/main/README.md
- Proof matrix: https://github.com/ehsandto/bounded-policy-compiler/blob/main/LIVE_PROOFS.md
- Sanitized ledger: https://github.com/ehsandto/bounded-policy-compiler/blob/main/PROOFS.json
- Contract Explorer: https://explorer-studio.genlayer.com/address/0x3B25560249B8D5b129e69dE0894E072AdB9F3e55
- Complete compilation: https://explorer-studio.genlayer.com/tx/0x71daf1569c2027c12d3e72b429e3d6407217d6cf4639f4789d7e20b3d604eb7c
- Uncertain compilation: https://explorer-studio.genlayer.com/tx/0x045c0083309e0a243432db433c20f5c8665a7c70829aee7991579c50a7a9f8b8
- Bad-hash HELD: https://explorer-studio.genlayer.com/tx/0xf4f61cdcb9d7ceef8e7eaebb0a76fdafbfae5edf0100760776996581472f3122
- Nonce replay (expected execution ERROR): https://explorer-studio.genlayer.com/tx/0x3695beef44d67126854d90ad5244a8da221c842e381ca3b0eb05126028189740
- Duplicate artifact (expected execution ERROR): https://explorer-studio.genlayer.com/tx/0xaa135cf3558e29432382808d43e5d2a97e965e1e1f0223cab51c71c8b7814f8a

Negative proof transactions in LIVE_PROOFS must retain their expected execution ERROR labels. Do not describe hypothetical simulation as verification of real people or permission to perform actual actions. Use the actual contribution date. No award or acceptance guarantee is made.
