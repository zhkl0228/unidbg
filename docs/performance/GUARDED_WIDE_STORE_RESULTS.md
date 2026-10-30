# Guarded ARM32 word and AArch64 doubleword stores

## Scope and implementation

Patch `0010` extends the narrow NOTDIRTY-store approach to little-endian 4-byte
ARM32 stores and 8-byte AArch64 stores, on 64-bit hosts only. It does not change
byte, big-endian or other-width helpers. No application name, fixture identifier,
result substitution, new cache or per-engine field is introduced.

The fast path requires both the original alignment contract and natural alignment,
a same-page access, no snapshot, no global write hook, an exact matching
`page | TLB_NOTDIRTY` tag, a valid existing RAM-section index, and a current RAM
region that is writable and not readonly. Every other case uses the original
store helper. The complete `notdirty_write` call is retained with the original
return address and the correct 4/8-byte size. Only after that call does the helper
use the current TLB entry's addend and perform the little-endian store. Natural
alignment is also required by the existing fast code-invalidation routine and
must not be removed. No dirty tracking or self-modifying-code check is skipped.

Separate diagnostic counts found 4-byte helper calls dominant in ARM32 execution
workloads and 8-byte calls dominant in AArch64 workloads, usually with NOTDIRTY
tags. Diagnostic instrumentation is not part of the shipped library, and its
elapsed times are not performance evidence. Counts alone do not prove every guard
or infer a speedup. The preceding penultimate-radix and Java name-equality
experiments were not accepted and are not included in this patch.

## Artifacts and correctness

- Baseline production code: `cae8988c5dd9738f464c5580644836cee23550e6` (`df03013f`
  adds only the original-upstream comparison report).
- Baseline native SHA-256: `65b3c8a52ec3f92d923bff14936a3a43eac235d723016a1a48f4a0bcf9b2d638`.
- Candidate native SHA-256: `27fcc8f9c7c6bf3708fd5fc4943941d008ffa493bde49283dff80e9689d32dfa`.
- Linux x86_64 library size: 4,307,560 bytes, 576 bytes larger than baseline.

The engine source matched pristine upstream plus published patches and this
patch using a scratch index; relinking reproduced the tested library byte-for-byte.
ARM32/ARM64 native units, callbacks, randomized stores/alignment, protection and
unmapped recovery, guest SMC, MMIO, COW, 200 snapshot restore/close cycles, exit
semantics and 16 Java tests passed. An additional wide-store test exercises
8-byte AArch64 protection/recovery/SMC/COW/MMIO and matches baseline output.
Its first MMIO assertion incorrectly assumed one callback for an 8-byte write;
both versions failed equally. The corrected test aggregates callbacks by offset
and passes both. This is a test correction, not an engine bug fix.

An AArch64 8-byte section-index test also passed nonidentity high physical addresses,
virtual aliases, collision/victim reuse, topology/slot replacement, protection/hooks,
explicit TLB flush, split unmap and memory snapshots. Its 160 instrumented stores
made zero fallback mapping queries. Existing callback-remapping limitations are
not claimed fixed. Flags excluded by source guards are not all independently
runtime-tested; this is not a claim of exhaustive watchpoint/BSWAP/IOMMU coverage.
Only Linux x86_64 was rebuilt and runtime-tested. Tests, samples and raw logs stay
outside Git.

## Measurement protocol

Complete frozen production runtimes, identical Java classes and dependencies,
fixed shared runtime paths, JDK8, 128 MiB heap, explicit identical official INFO
logging, unchanged workloads/warmup and fixtures. Every JVM's runtime files are
compared to a manifest; 11 class hashes/code sources, mapped native SHA and logging
configuration hash are witnessed. External jars/harness/JDK use shared paths and
are not rehashed every invocation; jars were rechecked against their frozen hashes
afterward. Output is bounded at 8 MiB with failure on overflow. No concurrent
benchmark/profiler ran; filesystem caches were not flushed.

Seven alternating pairs per eight workloads give 112 cold and 112 long observations.
A reconnect interrupted long repeat 6 after six records; these are preserved but
excluded. The entire repeat was rerun, giving the original 96 records plus 16
recovery records, never a spliced half-pair. The recovery runner exited successfully.
All 224 individual JVM exits and witnesses pass. Sensitivity excluding the recovery
block is reported below. No pilot or diagnostic results enter these estimates.

Effects are geometric paired current/baseline changes in percent; negative is
lower. Intervals are 95% percentile bootstrap from 20,000 paired repeat resamples
(seed 20261023). Suite summaries weight eight cases equally and resample whole
repeat blocks. Fixed case order and 4/3 baseline-first/current-first blocks are not
independent randomization. Intervals are exploratory, unadjusted for multiple
comparisons, not formal equivalence tests or a production-traffic forecast.

Long work is parsed from RESULT; cold work means the measured COLD warm phase,
not the first generic ns field (startup). Whole-process wall includes setup,
oracle preparation, loading, initialization, work, shutdown and witnesses.
Telegram uses a JCE oracle, TT a golden value, JNA ABI/version/checksum checks and
map signatures are checked; SG has completion checks but no independent business
output hash. Hash witnesses establish the implementation, not business correctness.

## Formal long results

| Workload | Work time change [95% CI] | Process wall change [95% CI] | Peak RSS change [95% CI] |
|---|---|---|---|
| Small-map signing | +0.17 [-2.47, +2.58] | +0.31 [-2.19, +2.66] | +1.31 [+0.53, +2.11] |
| Large-map signing | +2.20 [-0.63, +5.75] | +2.29 [-0.49, +5.67] | +0.68 [-0.54, +2.05] |
| Security library 4K | -7.30 [-8.87, -5.72] | -7.08 [-8.62, -5.36] | +0.17 [-0.87, +1.19] |
| Security library 64K | -11.85 [-12.68, -11.08] | -11.34 [-11.86, -10.72] | -1.29 [-3.04, +0.33] |
| TT repeated calls | -1.41 [-3.09, +0.68] | -1.50 [-2.95, +0.36] | +0.28 [-1.03, +1.55] |
| JNA ARM64 | -0.44 [-3.22, +2.57] | -0.14 [-3.10, +3.25] | -0.16 [-0.71, +0.41] |
| Telegram ARM32 | -13.30 [-15.98, -10.81] | -11.72 [-13.42, -9.88] | -1.35 [-5.18, +1.19] |
| Telegram ARM64 | -9.45 [-12.21, -6.85] | -8.42 [-11.03, -6.26] | -0.53 [-1.20, +0.03] |

Equal-case work falls **5.34% [4.48%, 6.20%]**, wall 4.84% [3.86%, 5.79%],
and process CPU 4.23% [3.13%, 5.23%]. Excluding the recovery block, work still falls
5.03% [4.33%, 5.76%], so the primary benefit is not recovery-driven. RSS is -0.12%
[-0.40%, +0.19%] and current-thread Java allocation -0.045% [-0.096%, +0.004%].
Allocation is not retained heap or native allocation; process RSS is not a leak test.

The benefit is concentrated in SG and Telegram. Map, TT and JNA intervals do not
establish reliable work improvements. Initially small-map RSS rose 1.31%
[0.53%, 2.11%], with medians 1,028,064 to 1,045,076 KiB (about 16.6 MiB).
Large-map work was +2.20% [-0.63%, +5.75%], with all three current-first pairs
unfavorable (+5.71% geometric mean). These observations motivated independent
confirmation; they are not erased from the formal experiment.

## Cold results and adverse observations

The eight-case cold suite has no clear whole-process gain: wall -0.41%
[-1.73%, +1.01%], CPU -0.22% [-1.58%, +1.35%]. RSS is -0.50%
[-0.93%, -0.08%]. Individual cold work includes clear Telegram improvements,
but this is not universal cold-start acceleration.

Initial adverse phase observations include TT load +7.12% [0.91%, 13.82%]
(medians 55.83 to 59.38 ms), JNA OnLoad +5.08% [1.46%, 8.94%]
(13.00 to 13.66 ms), JNA warm +6.66% [3.45%, 9.47%]
(0.515 to 0.549 ms), Telegram64 close +17.77% [2.37%, 40.32%]
(1.181 to 1.298 ms), and Telegram64 RSS +0.71% [0.07%, 1.51%].
The short phase durations and multiple comparisons warrant caution, not dismissal.

## Independent confirmation, not pooled

Fourteen new alternating pairs each were collected for cold TT/JNA/Telegram64
(84 JVMs) and long small/large-map (56 JVMs). All 140 unique row exits, captures,
class/native/configuration witnesses pass. The final orchestration exit could not
be recovered after a brief transport outage; individual completed records and
pair completeness were verified. These data are kept separate from the first
seven-pair experiment. Each selected case has 7/7 order balance, not randomization.

| Confirmed metric | Independent change [95% CI] |
|---|---|
| Small-map long RSS | -0.41 [-1.13, +0.34] |
| Large-map long work | -1.91 [-4.18, +0.49] |
| TT cold load | -1.43 [-7.09, +4.61] |
| JNA cold OnLoad | -3.62 [-8.39, +0.83] |
| JNA cold warm | +3.39 [-8.52, +18.17] |
| Telegram64 close | +3.89 [-5.22, +15.01] |
| Telegram64 cold RSS | -0.32 [-1.27, +0.64] |

The initial adverse memory/map-work/load observations were not consistently reproduced,
but wide intervals do not prove absence of regression. New adverse evidence is
retained: JNA startup is +3.14% [0.28%, 6.10%]; arithmetic means are 157.808 to
162.839 ms, paired mean difference +5.031 ms with additive interval
[+0.590, +9.594] ms. This is a measured difference, not a bound on future costs.
TT cold warm is +10.05% [-1.23%, +24.39%], and JNA warm remains uncertain.

Confirmation whole-process wall is TT +1.49% [-1.24%, +4.31%], JNA +1.60%
[-0.76%, +4.14%], and Telegram64 -0.73% [-3.86%, +2.52%]. None establishes a
whole-process slowdown, but TT/JNA estimates and bounds still allow a meaningful
small regression. Do not call them proof of no regression. Corresponding RSS
intervals span neutrality. Telegram64 cold warm improvement repeats at -9.78%
[-12.47%, -7.13%].

## Interpretation

Accept this as a generic long-workload optimization with measured near-neutral
aggregate memory and explicit cold-stage tradeoffs/uncertainty, not as universal
acceleration or strict no-regression. It adds no persistent cache, but that alone
does not guarantee zero RSS growth. No claim is made that every startup stage,
every workload or every host improves. The independent confirmation does not
replace the initial adverse observations.

These results are incremental against cae8988, not a new cumulative upstream
comparison. Do not multiply them into the earlier 1.44x suite result. Overall
20x remains unachieved; the original-upstream report describes its tested version.

## Raw-data audit identifiers

- Formal cold JSONL SHA-256: `793733f30c7f755621355dbd5a831a74d9c31d33173bef57aafa5d2d75f8a260`.
- Formal long complete JSONL SHA-256: `0b2f2b7ebf97adc3be9bf0b5e2ea6e2d0a1c68e15cc5b7f52a6405d8b78568b2`.
- Confirmation cold JSONL SHA-256: `71f28cb6a077f6b7d073404e15dd5c79fc694c62312f23cafb38eaf262a07f8f`.
- Confirmation long JSONL SHA-256: `d0084c21b2a58b44efc073fb6993743a94fd57fe40ab74ac1d7094acd1acf527`.
