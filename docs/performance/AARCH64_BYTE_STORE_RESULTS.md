# Guarded AArch64 NOTDIRTY byte-store handling

Patch 0009 specializes the AArch64 helper's common NOTDIRTY RAM-byte-store
case. It does not bypass dirty tracking or self-modifying-code invalidation.
The original notdirty_write call, arguments and return address are retained;
only after it returns is the current entry addend read and the byte stored.
Other paths retain the original store_helper through an outlined slow wrapper.

Admission requires a 64-bit host, AArch64 target, satisfied original alignment,
no snapshot, no write hook, an exact page|TLB_NOTDIRTY write tag, a valid existing
RAM section index and a current writable, non-readonly RAM region. All other
flags, misses, MMIO, watchpoints, protection/recovery and COW use the old path.
No cache, field, persistent pointer, SDK-name check or result substitution is added.
ARM32 retains the original implementation; its cputlb object .text is byte-identical
to the baseline. This is an architecture-level optimization, not an application switch.

A preceding all-architecture experiment improved Telegram ARM64 but regressed
large-map ARM32 work by 3.49% [1.87%,5.25%] in all seven pairs; it was rejected.
A zero-special-flag helper shortcut had zero measured coverage: ordinary stores
already bypass this helper in generated code. Neither experiment was published,
and neither experiment's timings are mixed into the results below.

## Validation and scope

Baseline: e737a30d7039287615402f321fed681e913b2047.
Baseline native SHA-256: 02abaabe21a2a2a375c65c24efd2fcd81076b77080ef4c7b118aae981cf76b78.
Candidate native SHA-256: 65b3c8a52ec3f92d923bff14936a3a43eac235d723016a1a48f4a0bcf9b2d638.
Native library size: 4,306,728 to 4,306,984 bytes (+256 bytes).

ARM32/ARM64 upstream units, 16 Java regressions and private callback, randomized
store, alignment, permission/recovery, guest SMC, MMIO, COW, ownership/remapping
and 200 snapshot restore/close checks passed. The preceding all-architecture
variant additionally passed extended exit and section-index tests. Existing
known write-callback-remapping limitations are not claimed fixed. Guards exclude
IOMMU/subpage cases; this is not a claim of new runtime coverage for every such case.
The full upstream-plus-patches source tree matched a scratch index, and rebuilding
reproduced the tested library byte-for-byte. Only Linux x86_64 was rebuilt and
runtime-tested. Tests, samples, diagnostics and raw logs remain outside Git.

## Measurement

Java 8, Linux x86_64, fixed 128 MiB heap, unchanged Java classes. Both arms use
identical native and Java runtime paths. Each fresh JVM reports its mapped native
SHA. Seven alternating pairs per case yield 112 cold and 112 long runs; all 224
record exit=0 and matching native hashes. The runner completed with exit=0.
The baseline-first/candidate-first order is 4/3 pairs, confounded with repeat parity.
No concurrent benchmark/profiler; OS caches were not cleared.

Telegram JCE, TT golden and JNA ABI witnesses passed; map signatures matched.
SG records successful work and process completion, not an independent business
output hash. A library hash proves which implementation ran, not business correctness.

Changes below are paired geometric candidate/baseline time or RSS changes in
percent: negative is lower. Per-case 95% percentile intervals use 20,000 paired
bootstrap resamples (seed 20261023). Suite summaries resample whole repeat blocks
and weight the eight cases equally. No outliers are removed, no multiple-comparison
correction is applied, and seven pairs do not establish formal noninferiority.
These are incremental results, not a comparison against original upstream.

| Long workload | Work time change [95% CI] | Process wall change [95% CI] | Peak RSS change [95% CI] |
|---|---|---|---|
| Small-map signing | +0.38 [-0.72,+1.31] | +0.27 [-0.80,+1.24] | -0.45 [-1.44,+0.40] |
| Large-map signing | +0.20 [-2.43,+2.59] | +0.69 [-1.85,+2.99] | +0.09 [-1.50,+1.60] |
| Security library 4K | +0.85 [-1.89,+4.07] | +0.91 [-1.85,+4.14] | -0.09 [-0.67,+0.58] |
| Security library 64K | -1.32 [-5.20,+2.11] | -1.31 [-4.83,+1.66] | -0.10 [-1.17,+0.92] |
| TT repeated calls | +0.45 [-2.81,+3.92] | +0.40 [-2.50,+3.42] | +0.92 [-0.20,+1.93] |
| JNA ARM64 | -0.51 [-3.50,+3.31] | -0.93 [-3.81,+2.64] | +0.53 [-0.41,+1.56] |
| Telegram ARM32 | -1.24 [-4.63,+2.67] | -1.20 [-3.50,+1.22] | +0.24 [-0.56,+1.02] |
| Telegram ARM64 | -10.17 [-13.22,-6.98] | -9.72 [-12.68,-6.75] | +0.78 [-0.03,+1.57] |

Telegram ARM64 process CPU falls 9.07% [6.24%,11.90%]; wall improves in both
order strata (-8.14% and -11.78%). The other cases do not establish throughput
improvements or sustained regressions. In particular, large-map ARM32's earlier
clear regression is not reproduced, but its wall interval still permits ~3% loss.

Equally weighted long work falls 1.48% [0.33%,2.74%], wall 1.42% [0.47%,2.34%],
and CPU 1.57% [0.57%,2.50%]. Excluding Telegram64, wall is -0.17% [-1.18%,+0.79%].
The gain is concentrated, not universal. Equal-weight RSS is +0.24% [-0.003%,+0.47%];
individual long RSS intervals include neutrality. No new persistent structure
is not a guarantee of zero process-memory growth.

Cold whole-process wall is +0.61% [-0.69%,+1.92%], CPU +0.84% [-0.50%,+2.21%],
and RSS +0.17% [-0.10%,+0.44%]: no broad startup improvement. All individual cold
wall intervals cross neutrality. TT cold CPU +4.70% [+1.77%,+7.89%] and security
64K cold RSS +0.68% [+0.29%,+1.13%] are adverse exploratory observations retained
for confirmation, not erased because the ARM32 target code is unchanged.

Overall 20x performance is not achieved. This change must not be represented as
universal acceleration, cold-start acceleration or a production memory bound.

## Independent cold confirmation

A separate 14 alternating pairs each for TT and security 64K (56 fresh JVMs,
all exit/hash checks passing) was run without pooling or replacing the initial
results. TT CPU was -0.05% [-2.21%,+2.04%]; security 64K RSS was +0.03%
[-0.38%,+0.43%]. Thus the two initial adverse signals were not reproduced.
TT wall was +1.10% [-1.02%,+3.00%]; security 64K wall -0.56% [-3.05%,+1.67%].

A different small adverse signal appeared: TT cold RSS +0.40% [+0.15%,+0.67%],
with both orders positive, approximately 350 KiB by arithmetic means
(87,871 to 88,220 KiB). This is retained as a small memory tradeoff/observation,
not called a leak or dismissed. Security 4K's initial cold wall estimate was
+4.05% [-0.55%,+10.13%] and was not separately confirmed; small-sample uncertainty
still permits practically meaningful cold regressions. Acceptance is limited
to an ARM64 fast-path improvement with these qualifications, not strict global
nonregression. No original measurement or adverse observation was discarded.
