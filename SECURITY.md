# Security model

Experimental and unaudited. Hypothetical document interpreter only; never a real-world identity, authorization, compliance or physical-safety oracle. No asset balances, approvals, payments or contract calls exist.

## Controls

- Source text acquired independently inside each validator's nondeterministic flow; caller supplies coordinates, not evidence body or result.
- Full commit/hash binding, restricted HTTPS host/path, bounded UTF-8 bytes and complete table coverage.
- Every semantic cell independently recomputed; exact canonical report comparison, no confidence tolerance.
- Post-consensus schema/source/config/binding validation before installing any artifact.
- Permissionless compilation; authenticated creator/nonce attempts; content-addressed global deduplication; no admin overrides or mutable heads.
- HELD cannot poison the successful artifact namespace; no pending job or locked funds.
- Root-bound simulation rejects malformed masks and authorizes nothing. An ALLOW answer requires every consistent completion to allow.
- Unknown, conflict and mixed cells are explicit unresolved output, never optimistic approval.
- 1–4 predicates, 16 cells maximum, 8 KiB source maximum, 32 attempts per creator.

## Residual risk

Published documents can be untrustworthy or outdated. Source hashes provide integrity, not authority/current freshness. Predicate definitions are hypothetical vocabulary and may omit required real-world conditions; the compiler is instructed to return UNKNOWN when these matter. Shared model failure or prompt injection can survive consensus. No mathematical proof establishes natural-language semantic correctness.

Artifacts are immutable. Consumers must choose the exact source revision, predicate domain and root; no administrative correction silently changes a compiled function. If interpretation policy needs correction, use a new deployment. Partial-context results do not verify a real operator's facts. These are not permissions to operate machinery; fixtures are fictional.

Signing uses a dedicated zero-balance test account through its native encrypted keystore and OS vault. Never expose keys, raw receipts, validator configurations or credentials. Notify the repository maintainer privately before publishing exploitable security details. No independent professional audit is claimed.
