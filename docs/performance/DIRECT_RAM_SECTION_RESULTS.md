# Direct lookup of a prevalidated RAM section

Patch `0008` specializes only the cached ordinary-RAM store lookup introduced by
`0006`. Fill-time admission already proves that the section belongs to both the
selected CPU dispatch and the global physical memory dispatch. The store still
requires a matching actual write TLB tag, a non-sentinel index, no snapshot and
no write hook, before any callback. The new helper resolves that index against
the current global dispatch, avoiding repeated attribute-to-address-space
selection. General iotlb_to_section and all fallback paths are unchanged.

No pointer is retained across callbacks, reentry, refill or topology changes.
No field, cache or allocation is added; entry layouts are unchanged. This is not
a shortcut past guest MMU translation or permission checks. The implementation
relies on the existing serialized mapping-update/TLB-invalidation contract.

## Validation

Baseline: `462a85d3d267cae8b011f8efcfff6cbf80e9b939` (native `e9bbb09e…dd844`).
Candidate native SHA-256:
`02abaabe21a2a2a375c65c24efd2fcd81076b77080ef4c7b118aae981cf76b78`.

Forty-five upstream ARM32/ARM64 units, 16 Java regressions, callback/nested-exit
checks and the extended exit-semantics suite passed. Private differential checks
matched for randomized writes, unaligned accesses, permissions/recovery, guest
self-modifying code, MMIO and COW; nonidentity high physical addresses, aliases,
read-driven victim swaps, section renumbering, explicit TLB flush, split unmap,
and 200 memory-snapshot restore/close cycles were covered. IOMMU/subpage cases
remain excluded by original admission guards rather than newly accelerated.

The complete upstream 2.1.4 plus patches 0001–0008 tree matched a scratch index,
and rebuilding reproduced the tested native binary exactly. Only Linux x86_64
was rebuilt/runtime-tested. Tests, samples and raw logs remain outside Git.

## Measurement

Java 8, Linux x86_64, fixed 128 MiB heap; identical runtime native path and Java
paths in both arms, with mapped native hashes verified. Seven alternating pairs
for each of eight workloads produced 112 cold and 112 long fresh-JVM runs.
No benchmark/profiler ran concurrently with another benchmark. OS caches were
not cleared. Results below are incremental, not an original-upstream total.

Ratios are paired geometric means. Time is baseline/candidate; memory is
candidate/baseline. Exploratory 95% intervals use 200,000 paired bootstrap
resamples; no multiple-comparison adjustment or formal equivalence claim.

| Workload | Operation speed B/C [95% CI] | Peak RSS C/B [95% CI] |
|---|---|---|
| Small-map signing | 1.0132 [0.9896, 1.0373] | 0.9953 [0.9854, 1.0041] |
| Large-map signing | 1.0213 [1.0034, 1.0375] | 1.0012 [0.9879, 1.0187] |
| Security library 4K | 1.0322 [1.0048, 1.0594] | 1.0039 [0.9969, 1.0094] |
| Security library 64K | 1.0311 [1.0172, 1.0453] | 1.0047 [0.9972, 1.0155] |
| TT repeated calls | 1.0422 [1.0271, 1.0587] | 1.0173 [1.0097, 1.0259] |
| JNA ARM64 | 0.9901 [0.9691, 1.0091] | 0.9956 [0.9860, 1.0046] |
| Telegram ARM32 | 1.0493 [1.0241, 1.0730] | 0.9954 [0.9897, 1.0012] |
| Telegram ARM64 | 1.0486 [1.0282, 1.0695] | 0.9987 [0.9932, 1.0048] |

Six workloads show operation and whole-process wall improvements whose intervals
exclude neutrality, approximately 2–5%, with favorable directions in both order
strata. Small-map signing is inconclusive. JNA's approximately 1% slower point
estimate changes direction by order and does not establish a persistent loss.

The TT peak-RSS increase is repeatable in every pair and both orders: geometric
means 121,007 to 123,105 KiB, approximately +2.05 MiB / +1.7%. Measured Java
allocation is exactly unchanged. This small process-memory tradeoff is retained
explicitly; unchanged data structures do not imply zero RSS cost or a hard
memory bound. Other long-workload RSS intervals include neutrality.

An equally weighted summary of this fixed suite gives operation speed 1.0283
[1.0248, 1.0318], whole-process wall 1.0262 [1.0220, 1.0304], and RSS C/B 1.0015
[0.9979, 1.0060]. These are not universal production estimates.

Cold tests establish no individual whole-process wall or CPU improvement. Small
phase observations are exploratory. Cold small-map RSS rises approximately 0.56%
[0.23%, 0.90%], not reproduced in its long runs. Negative point estimates and
uncertainty are not excluded from the report. Overall 20x speedup is not achieved.
