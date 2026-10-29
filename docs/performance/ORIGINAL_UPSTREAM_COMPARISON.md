# Original upstream comparison through cae8988

Measured 2026-10-23 on one Linux x86_64 host with Java 8. This is a cumulative,
whole-version comparison, not multiplication of incremental results.

- Original production baseline: `2ba8156eef31501ebd35194adb5795ef3e01a285`.
- Optimized production version: `cae8988c5dd9738f464c5580644836cee23550e6`.
- Original native SHA-256: `76924bad55c3d4b5361678aa01b65f8a8639bda775fea190e138b021872bfd15`.
- Optimized native SHA-256: `65b3c8a52ec3f92d923bff14936a3a43eac235d723016a1a48f4a0bcf9b2d638`.

## Isolation and checks

Both commits were freshly built with the same offline Maven dependencies and JDK.
Each runtime contains the complete production classes/resources of API, Android,
Unicorn2, Dynarmic, Hypervisor and KVM modules. No old partial class overlay or
current checkout's classes fill holes in the baseline. Identical third-party jars
and harness classes are shared; each arm is copied to the same runtime path.
Every file is checked against its frozen manifest before each JVM. Eleven core
class hashes and code sources, and the actually mapped native library SHA, are
checked in each run. Only Unicorn2 is exercised by this comparison.

Both use the byte-identical official test INFO logging configuration via an
explicit file URL. Its hash is witnessed, and relevant logger levels are checked
before and after work. Heap options are `-Xms128m -Xmx128m`; fixtures, arguments,
warmup, working directory and seed restoration are identical. No profiler or
other benchmark ran concurrently. OS caches were not flushed. Cold means a fresh
JVM, not cold filesystem caches. The capture limit is 8 MiB with failure on excess.

Seven alternating pairs per case produce 112 cold and 112 long runs. All 224
passed process, capture, configuration, class and native checks; the runner exited
successfully. Maximum captured output was 3,568 bytes cold and 3,414 bytes long.
Telegram uses JCE PBKDF2 comparison; TT uses a fixed golden hash and repeat checks;
JNA checks version/checksum/ABI; map signing checks deterministic output (the small
map also has an independent golden value). SG completion is not an independent
business-output oracle. Runtime hashes alone do not prove business correctness.
Tests, samples, profiler output and raw logs are deliberately not committed.

## Statistics

Timing ratios are baseline/current: greater than 1 means faster. RSS and allocation
ratios are current/baseline: less than 1 means lower. Estimates are paired geometric
means with 95% percentile intervals from 20,000 paired bootstrap resamples. Suite
estimates weight eight cases equally and resample entire repeat blocks. Seven
pairs on one host, fixed case order, four baseline-first and three current-first
repeats, and no multiplicity adjustment limit generalization. These are not traffic
weighted production forecasts or formal universal noninferiority guarantees.

## Long workloads

| Case | Work speedup [95% CI] | Process wall speedup [95% CI] | Peak RSS ratio [95% CI] |
|---|---|---|---|
| Small-map signing | 1.974 [1.918, 2.044] | 1.947 [1.892, 2.014] | 0.981 [0.975, 0.987] |
| Large-map signing | 2.029 [1.997, 2.069] | 1.955 [1.925, 1.990] | 0.969 [0.947, 0.995] |
| Security library 4K | 1.257 [1.217, 1.304] | 1.240 [1.202, 1.285] | 0.991 [0.981, 1.000] |
| Security library 64K | 1.200 [1.167, 1.241] | 1.184 [1.155, 1.218] | 0.966 [0.960, 0.974] |
| TT repeated calls | 1.583 [1.549, 1.622] | 1.558 [1.518, 1.601] | 0.274 [0.263, 0.285] |
| JNA ARM64 | 1.230 [1.197, 1.264] | 1.218 [1.188, 1.249] | 1.006 [0.996, 1.015] |
| Telegram ARM32 | 1.208 [1.184, 1.235] | 1.197 [1.178, 1.219] | 0.933 [0.926, 0.941] |
| Telegram ARM64 | 1.455 [1.426, 1.483] | 1.443 [1.408, 1.475] | 0.919 [0.910, 0.928] |

Long work counts: map2 50,000 calls, map100 1,000 calls, SG 4K 1,000 encrypt/decrypt round trips,
SG 64K 100 round trips (two native commands per round trip), TT 1,000,000 calls, JNA 500,000 iterations (three native calls each), Telegram32 one
100,000-iteration PBKDF2 and Telegram64 three. Long warmup is 20 map calls (plus one expected-value call), 10 SG round trips,
20,000 TT calls (plus one golden call), 20,000 JNA iterations and one Telegram
PBKDF2. Cold runs omit these warmup loops, but Map/TT still have a validation
call before measurement; fresh JVM does not mean first native invocation.
Timed work is parsed independently
from RESULT, not startup fields. All eight work intervals remain above 1 in each
order stratum; suite work is 1.455 baseline-first versus 1.468 current-first.

Equal-case suite work is **1.460x [1.452, 1.469]**, process wall **1.438x
[1.432, 1.445]**, and process CPU 1.390x [1.383, 1.396]. Peak RSS ratio is
0.825 [0.821, 0.830], and measured current-thread Java allocation ratio is
0.873 [0.873, 0.874]. Allocation is cumulative allocated bytes, not retained heap.

Memory improvement is uneven. TT median peak RSS falls from 409.14 to 116.69 MiB.
Excluding TT, the other seven cases' equal-weight RSS ratio is 0.966 (descriptive
sensitivity only), not the full suite's 17.5% reduction. JNA's estimate is +0.64%
with an interval spanning neutrality. SG 4K RSS is 0.9911 [0.9811, 1.0004],
also spanning neutrality despite three-decimal rounding in the table. Process RSS includes native allocations and
is not limited by Java Xmx; it does not establish leak elimination or a memory cap.

## Fresh-JVM workloads

| Case | Process wall speedup [95% CI] | Library-load speedup [95% CI] | Peak RSS ratio [95% CI] |
|---|---|---|---|
| Security library 4K | 1.090 [1.008, 1.173] | 1.292 [1.168, 1.409] | 1.012 [0.973, 1.052] |
| Security library 64K | 1.062 [1.041, 1.082] | 1.145 [0.990, 1.281] | 0.993 [0.979, 1.005] |
| Telegram ARM32 | 1.145 [1.106, 1.184] | 1.458 [1.381, 1.534] | 0.916 [0.908, 0.923] |
| Telegram ARM64 | 1.305 [1.258, 1.348] | 2.249 [2.156, 2.358] | 0.886 [0.880, 0.892] |
| Small-map signing | 1.064 [1.023, 1.106] | 1.175 [1.088, 1.278] | 1.016 [1.007, 1.023] |
| Large-map signing | 1.063 [0.983, 1.137] | 1.195 [1.105, 1.301] | 0.985 [0.977, 0.995] |
| TT repeated calls | 1.054 [1.024, 1.088] | 1.166 [1.075, 1.252] | 1.015 [1.009, 1.021] |
| JNA ARM64 | 1.023 [0.997, 1.046] | 1.103 [0.972, 1.217] | 0.998 [0.992, 1.003] |

Equal-case cold process wall is **1.098x [1.088, 1.106]**, CPU 1.068x
[1.055, 1.079], and RSS ratio 0.976 [0.970, 0.982]. Whole-process wall includes
harness setup/oracle preparation, startup, loading, initialization, one measured
work iteration plus setup/validation calls, shutdown and runtime witnesses; it is not
pure loader time. The Telegram load phases improve 1.458x and 2.249x respectively.

Not every phase or memory measurement improves. Cold small-map and TT peak RSS
ratios are 1.0155 [1.0073, 1.0234] and 1.0153 [1.0093, 1.0205]. Small-map JNI_OnLoad
speed ratio is 0.871 [0.755, 0.994], with medians approximately 0.503 to 0.577 ms;
this small absolute regression is retained. Large-map OnLoad is noisy and its
interval crosses neutrality. Some startup, load and cold-work intervals also
cross neutrality; do not describe all individual phases as faster. Cold Java
allocation is available only for SG/map, so no eight-case allocation claim is made.

## Invalid first attempt retained for audit

An earlier isolation attempt omitted test resources and therefore the logging
configuration. Reload4j defaults to DEBUG when unconfigured; direct Inspector dumps
still print even when no appenders are installed. This produced about 27 GiB of
output, exhausted disk space and left the long run incomplete at 107 records.
The cold run and interrupted long run are excluded from every estimate above.
The original long output was losslessly compressed and its decompressed SHA
verified before replacing the redundant uncompressed file. The corrected INFO
cold and long runs are entirely fresh; no half-pair, DEBUG result, pilot, rejected
candidate, old class-overlay result or standalone JNI microbenchmark is pooled.

This comparison establishes about 1.44x whole-process speed on this test suite,
not the requested overall 20x. No SDK-name, sample hash, fixed output or application
special case is used by the optimizations. Current evidence does not establish
20x acceleration, universal speedup, or strictly non-increasing memory in all cases.

## Audit identifiers

- Corrected cold raw JSONL SHA-256: `870ef53ab5104a6617942ba242c8f761cdc3fbb275e93c341c6110dcf682cb19`.
- Corrected long raw JSONL SHA-256: `b60b1019446e157ecddab5d64fdf1f6421f96e29edc4fa4b63d7ec38c7f2f286`.
- Excluded long raw SHA-256: `d2ffe9e1b20a03226d90891669690843fff03c4781376343ccdd798e08e7411b`.
