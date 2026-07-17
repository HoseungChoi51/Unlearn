# Artifact identity ledger

## Scope and naming rule

This file is the compact human index for artifact identities added after
coverage v7. Machine-readable configs, manifests, schemas, and frozen source
constants remain authoritative. Other documentation should normally refer to
the stable name in the first column and link the exact file instead of copying
its digest.

“Semantic” identifies a domain-separated logical record. “File” identifies
the exact checked-in bytes. These are different identities even when they
describe the same artifact.

## Fifteenth tranche and coverage v8

| Stable name | Exact artifact or source | Identity kind | SHA-256 | Bytes |
|---|---|---|---|---:|
| `process-lifecycle task set` | [`process-lifecycle-delta` promotion in coverage v8](configs/executable-method-development-coverage-v8.json) | Semantic task set | `2add107b1b16270837968e477662f721faef4ea32b4432b5efe41c5af8097d4d` | — |
| `process-lifecycle discrimination` | [`process-lifecycle-delta` promotion in coverage v8](configs/executable-method-development-coverage-v8.json) | Semantic all-profile discrimination | `1a94ccdd0d75698973f172daa5a90e660747718969b05f0d6b414ac934c7e383` | — |
| `fifteenth added registry` | [Fifteenth registry source](src/cbds/executable_static_fifteenth_registry.py) | Semantic registry | `2d2773bcab7f83c99638541803516d893d3749b6c7b1b0091c6633f1c54493a5` | — |
| `fifteenth cumulative suite` | [Fifteenth registry source](src/cbds/executable_static_fifteenth_registry.py) | Semantic cumulative suite | `fce6939985a541c0bdb0e9f456b0e713f835b283a001e8a0f124047abe6ad99a` | — |
| `fifteenth cumulative fixture catalog` | [Fifteenth manifest](reports/executable-fifteenth-tranche/manifest.json) | Semantic catalog | `ebcf536efe7c34778faff900ac577ad4919e258711af3f0527c47ff8aab8ff33` | — |
| `fifteenth manifest file` | [Fifteenth manifest](reports/executable-fifteenth-tranche/manifest.json) | File bytes | `78e0add5e6eb3e694238caa9603109f4c810937e6948b17ae9106bb07885ff1b` | 56,276 |
| `reviewed lifecycle Bash literal` | [`_HAND_AUTHORED_BASH` UTF-8 payload in the reviewed canary source](tests/test_executable_process_lifecycle_delta_bash_canary.py) | Literal bytes, not source-file bytes | `bb1886ebf06f45c51cc534afe9c29241b2f502991703d02d1e87cc8501189638` | 15,813 |
| `lifecycle canary aggregate vector` | [Reviewed canary source](tests/test_executable_process_lifecycle_delta_bash_canary.py) | Semantic test vector | `b5db3d65c4fa72e0ab1a0a743d93c1b36542fbde470b94f9f078b4ec4d48a88c` | — |
| `lifecycle canary boundary vector` | [Reviewed canary source](tests/test_executable_process_lifecycle_delta_bash_canary.py) | Semantic test vector | `ad75dbef925bbd90f383ba5de7a3009078238b75416e94e445c163b4010efff8` | — |
| `lifecycle canary failure vector` | [Reviewed canary source](tests/test_executable_process_lifecycle_delta_bash_canary.py) | Semantic test vector | `7f4d367e4f000335bdd5dcca6a3c49749e5a86e84ba66861abc54a26b6624bbd` | — |
| `integrated process-lifecycle family` | [Coverage v8](configs/executable-method-development-coverage-v8.json) | Semantic family record | `f5ef27ca10caedbad1e6e3652e6020c12524309698970438946969cf89310510` | — |
| `coverage v8` | [Coverage v8](configs/executable-method-development-coverage-v8.json) | Semantic coverage | `606ba0a90adc8f19cafd7495ab24ff117f31edb653b4b3cf8b6917a14b70ad05` | — |
| `coverage v8 config file` | [Coverage v8](configs/executable-method-development-coverage-v8.json) | File bytes | `3cec2f00a47017ea0e602b4609666df877b8a6f4ca5d262882a1251df27c968a` | 27,209 |
| `coverage v7-to-v8 migration` | [Coverage v7-to-v8 migration](configs/executable-method-development-coverage-v7-to-v8-migration.json) | Semantic migration | `31ce6e0a45f49bc6c31208f3429666aa5d713b78d2186ab7ef228ed768f8e5ff` | — |
| `coverage v7-to-v8 migration config file` | [Coverage v7-to-v8 migration](configs/executable-method-development-coverage-v7-to-v8-migration.json) | File bytes | `56291522a93c1e54cfc9999bf177d2ec0c351ac42b5d886c998e065495eaed0a` | 6,064 |
| `coverage v8 schema copies` | [Coverage v8 schema](executable-method-development-coverage-v8.schema.json) and [packaged copy](src/cbds/schemas/executable-method-development-coverage-v8.schema.json) | File bytes; two identical copies | `4114a414d137686c9b789ba286c2aba99e0823a22366bf2e5c0f4e95d479b438` | 11,010 each |
| `coverage v7-to-v8 migration schema copies` | [Migration schema](executable-method-development-coverage-v7-to-v8-migration.schema.json) and [packaged copy](src/cbds/schemas/executable-method-development-coverage-v7-to-v8-migration.schema.json) | File bytes; two identical copies | `c7f7889edd0441ee2b50f0a8bfcdffb33f2a45ff1c0fae1ae7df6c5749fb488d` | 8,128 each |

The coverage-v8 predecessor is Git commit
`199eba7759cf49215a4e1da09dc59d2c175ee41f`. Its historical coverage-v7
identities remain recorded with the v7 artifacts and are not duplicated here.
