# StudioNet proof matrix

## Deployment and source

- Contract: [0x3B25560249B8D5b129e69dE0894E072AdB9F3e55](https://explorer-studio.genlayer.com/address/0x3B25560249B8D5b129e69dE0894E072AdB9F3e55).
- Gasless StudioNet, chain 61999; dedicated native test signer `0x7a413BB4AB62E31d62d4cD9efC8C8a8Dae37FB42`. No private key was exported or funds transferred.
- Contract and public fixture commit: [`57390a2190c5935792a86bbd6dc3bbfcbdb62902`](https://github.com/ehsandto/bounded-policy-compiler/commit/57390a2190c5935792a86bbd6dc3bbfcbdb62902).
- Deployed source matched the repository contract through `gen_getContractCode`; normalized source SHA-256: `2a51476e599e55c60a313d436477af4a2357f06215a7ea7d89b10d78be79d80f`.
- Source normalization: CRLF → LF, remove trailing whitespace/newlines, append one newline. Contract source has not changed since deployment; later commits add documentation/proof tooling only.
- [PROOFS.json](PROOFS.json) stores sanitized metadata, never raw validator configuration or credentials.

## Finalized transaction matrix

All six transactions finalized with MAJORITY_AGREE. Four executed SUCCESS: deployment, two compilations and one HELD attempt. Two deliberately executed ERROR. They are rejection proofs, not successful compilations.

| Step | Execution | Observed effect | Transaction |
| --- | --- | --- | --- |
| Deployment | SUCCESS | Contract created | [9f2f2f13](https://explorer-studio.genlayer.com/tx/0x9f2f2f134f24780c84c79a467faef6385913840dcdad04f7738dc6bb95380319) |
| Complete policy | SUCCESS | Full source acquired; all 8 semantic cells compiled into immutable artifact | [71daf156](https://explorer-studio.genlayer.com/tx/0x71daf1569c2027c12d3e72b429e3d6407217d6cf4639f4789d7e20b3d604eb7c) |
| Incomplete policy | SUCCESS | Four nonrevoked cases remain UNKNOWN; four revoked cases DENY | [045c0083](https://explorer-studio.genlayer.com/tx/0x045c0083309e0a243432db433c20f5c8665a7c70829aee7991579c50a7a9f8b8) |
| Wrong source commitment | SUCCESS | HASH_MISMATCH → HELD; no compiled artifact exists | [f4f61cdc](https://explorer-studio.genlayer.com/tx/0xf4f61cdcb9d7ceef8e7eaebb0a76fdafbfae5edf0100760776996581472f3122) |
| Reused nonce | **ERROR, expected** | `Attempt nonce used`; no overwrite | [3695beef](https://explorer-studio.genlayer.com/tx/0x3695beef44d67126854d90ad5244a8da221c842e381ca3b0eb05126028189740) |
| New nonce, same compiled configuration | **ERROR, expected** | `Artifact already compiled`; global content-address deduplication | [aa135cf3](https://explorer-studio.genlayer.com/tx/0xaa135cf3558e29432382808d43e5d2a97e965e1e1f0223cab51c71c8b7814f8a) |

## Final records and independently recomputed roots

| Attempt | ID | Status | Attempt root |
| --- | --- | --- | --- |
| `demo-complete` | `b01bea99f1a2bb6aedc7f8f6925836dfb9b0be5ac38d650da5b5d6c048aa5d6a` | COMPILED | `4dc3d7a398a0df69e80167aa0195c70f8ceb298917122431f752ce3b7cb73497` |
| `demo-unresolved` | `8c540942e030561d190e95d24925c5e6d91832e22b336ff6c3cc082c0c85da1a` | COMPILED | `9cdabcc18ba0d0389d99af1ca18b3d61bacf53a84b7afae72ea19e40a2d99622` |
| `demo-badhash` | `cd9a522ff95b4756d9257cced9266fca7181af1295fbef02aee12037a9619f7c` | HELD | `3af21c8c5a2e2b91bc24f58ea2cb5fa7d8b1b408ad54c340d4aae87a4b898d6d` |

| Compiled function | Artifact ID | Artifact root |
| --- | --- | --- |
| Complete policy | `07558997e8e6bd78555aacc0af92e7bebebd95f64b6b0b5d5178c0832ee24e15` | `7b2d134ce91bd620ebf76df099c1860cfe8c352bc2700a99089716b24a0bcad1` |
| Incomplete policy | `e24121fb2e32a438ab94db8c01c04361e7ac1f61e935770fa3b78408ad9df1e6` | `b9bfd15f9a26e9c8c34fd362ee4595cb19c77e614f583205955e09dc740ef479` |

Read checks recomputed attempt and artifact roots, matched the full acquired body's hash, verified configuration/content-address binding and compared all eight fully specified queries plus four partial queries per artifact. These **24 query checks are read-only calls**, not additional onchain transaction proofs.

### Truth tables read from finalized state

Predicate order: bit 0 `staff`, bit 1 `supervised`, bit 2 `revoked`. Action: `Use the workshop laser cutter`.

| Index | Staff | Supervised | Revoked | Complete policy | Incomplete policy |
| --- | --- | --- | --- | --- | --- |
| 0 | false | false | false | DENY | UNKNOWN |
| 1 | true | false | false | ALLOW | UNKNOWN |
| 2 | false | true | false | ALLOW | UNKNOWN |
| 3 | true | true | false | ALLOW | UNKNOWN |
| 4 | false | false | true | DENY | DENY |
| 5 | true | false | true | DENY | DENY |
| 6 | false | true | true | DENY | DENY |
| 7 | true | true | true | DENY | DENY |

### Material partial-context results

| Known mask / values | Consistent cells | Complete policy | Incomplete policy |
| --- | --- | --- | --- |
| `0 / 0` | All eight | UNRESOLVED | UNRESOLVED, has_unknown |
| `4 / 4` | 4, 5, 6, 7 | DENY | DENY |
| `5 / 1` | 1, 3 | ALLOW | UNRESOLVED, has_unknown |
| `4 / 0` | 0, 1, 2, 3 | UNRESOLVED | UNRESOLVED, has_unknown |

These are conditional document interpretations. They verify **neither an operator's identity nor whether actual supervision/revocation facts hold**. `hypothetical_only: true` is returned by the contract. No machinery operation, real permission, payment or safety certification is demonstrated.

## Source commitments

- [Complete fictional policy](https://raw.githubusercontent.com/ehsandto/bounded-policy-compiler/57390a2190c5935792a86bbd6dc3bbfcbdb62902/examples/workshop-policy.txt): `163d16b0c65fbfd602f4d79d5353d56d4b10793678d8a5279aa00c627c3f2fb0`.
- [Incomplete fictional policy](https://raw.githubusercontent.com/ehsandto/bounded-policy-compiler/57390a2190c5935792a86bbd6dc3bbfcbdb62902/examples/unresolved-policy.txt): `673bc8ffbee11530e3ce1d7847da3961a128fca85f3f9a8a8e450bdb7b847687`.

Both are authored fixtures from this repository, not independent authorities or real workplace policies. Source pinning establishes the exact published revision used, not current real-world applicability. Real network web and LLM calls were used for compilation; mocks were confined to local tests.

## Local versus live coverage

| Property | Local tests | Live evidence |
| --- | --- | --- |
| Complete semantic compilation | Passed | Complete policy artifact above |
| Silence remains UNKNOWN | Passed | Incomplete policy artifact above |
| Partial context cannot turn mixed/unknown cells into ALLOW | Exhaustive 2,304 cases | Material query cases above |
| Conflict label propagates as unresolved | Passed | Not artificially induced live |
| Independently rerun validator rejects changed cells/source/binding | Actual callback unit test passed | Network MAJORITY_AGREE; deliberate disagreement not claimed |
| Post-consensus forged config/body/table/binding rejected | Passed | Not injected live |
| Bad hash prevents installation | Passed | HELD attempt and absent artifact checked |
| HTTP/encoding/size failures | Passed | Not all forced live |
| HELD attempt cannot poison later successful compilation | Passed | Not claimed live |
| Nonce replay/global duplicate rejection | Passed | Expected ERROR receipts above |
| Complete four-predicate coverage and bit order | 81 partial-context cases passed | Live fixture uses three predicates |
| Malformed output, paths, predicates and masks | Passed | Not all forced live |

Verification: GenVM lint and SDK validation passed; 43 direct/unit tests passed; 4 SDK calldata roundtrips passed. Direct mode executes the leader, not distributed consensus; callback tests invoke the actual comparison function separately. This table does not relabel those tests as real network disagreement proofs. No independent professional security audit or guaranteed steward acceptance is claimed.

## Reproduce safely

```powershell
node --dns-result-order=ipv4first scripts/check.mjs source 0x3B25560249B8D5b129e69dE0894E072AdB9F3e55
node --dns-result-order=ipv4first scripts/check.mjs attempt 0x3B25560249B8D5b129e69dE0894E072AdB9F3e55 b01bea99f1a2bb6aedc7f8f6925836dfb9b0be5ac38d650da5b5d6c048aa5d6a
node --dns-result-order=ipv4first scripts/check.mjs attempt 0x3B25560249B8D5b129e69dE0894E072AdB9F3e55 8c540942e030561d190e95d24925c5e6d91832e22b336ff6c3cc082c0c85da1a
node --dns-result-order=ipv4first scripts/check.mjs attempt 0x3B25560249B8D5b129e69dE0894E072AdB9F3e55 cd9a522ff95b4756d9257cced9266fca7181af1295fbef02aee12037a9619f7c
```

For each known transaction use `check.mjs success HASH`; use `error HASH "Attempt nonce used"` or `error HASH "Artifact already compiled"` for the labeled rejection proofs. Never dump raw receipts: they may include private validator configuration. `complete-proofs.mjs` runs one documented step at a time and records sanitized hashes before receipt checks. A saved unknown broadcast without a hash requires manual sender-history inspection, never an automatic resend. Run only one runner at a time.
