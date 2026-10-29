# Avoid recompiling eligible warm ARM exit blocks

The `0007` engine patch avoids generating an empty translation block on an
eligible ARM32/ARM64 emulation exit. It invokes the existing WFI helper, preserving
its traps, pending-work behavior and longjmp handling. If that helper returns,
ordinary translation proceeds. The fast path requires already-valid full-page
code TLB entries for the current page and, at a boundary, its predecessor. It
performs no speculative MMU lookup. Stepping, ARM IT state, M-profile, special
translation flags, exit requests, edge-generated hooks and TLB-fill hooks retain
the old path. Callback/fault behavior remains covered by differential tests.

This is a generic exit invariant, not an SDK name check or result cache. No
per-emulator persistent field/cache is added. The check is isolated in an
out-of-line translation-miss wrapper; cached cpu_exec instruction/register layout
matches the baseline apart from the changed call target and assertion line.
Ordinary translation misses do acquire wrapper overhead, so universal speedup
is not claimed.

## Correctness and reproduction

- 45 upstream ARM32/ARM64 unit cases and 16 Java regression tests passed.
- 26 callback/timeout/nested-execution lines and 97 extended public-semantics
  lines matched baseline, including ARM, Thumb and A64 modes.
- 15 completed internal differential cases matched, covering WFI traps, pending
  interrupts, IT/configured exits and hardware single-step behavior. Three
  manually forced CPU single-step cases timed out in both arms and are NOT
  counted as passing stepping coverage.
- The complete upstream 2.1.4 plus patches 0001–0007 tree was verified against a
  scratch Git index. Rebuilding reproduced the tested native binary exactly.
- Only Linux x86_64 native code was rebuilt and runtime-validated. Other host
  binaries remain unchanged and require separate rebuilding/validation.

Published native SHA-256:
`e9bbb09e3c43795f4964a1eed3e07d49135520a887cbbf0275e2ffcb9e5dd844`.

Private tests, fixtures and raw logs are intentionally outside Git.

## Corrected measurement protocol

Baseline is commit `67df098` with native SHA `5d6898…289cb6b`; both arms use the
same Java implementation. Linux x86_64, Java 8, fixed 128 MiB heap. Seven
alternating fresh-JVM pairs per workload produced 112 cold and 112 long runs.
Native binaries are installed sequentially at the IDENTICAL runtime path, and
mapped native hashes are verified after each workload. No workload ran
concurrently with another benchmark or profiler. OS caches were not cleared.

Earlier different-path experiments suggested a roughly 4.5% JNA cold RSS
increase and slower JNI_OnLoad. An A/A control with the identical baseline
binary at two paths reproduced these effects (20 pairs, RSS C/B 1.0454), so they
cannot be attributed to the new native code. All earlier observations were
retained, but final performance claims use the corrected same-path protocol.
The underlying path/JIT mechanism has not been isolated.

## Long-workload results

Ratios are paired geometric means. Time ratios are baseline/candidate; RSS is
candidate/baseline. Exploratory 95% paired bootstrap intervals enumerate all
7^7 resamples; no multiple-comparison correction or equivalence claim is made.

| Workload | Operation speed B/C [95% CI] | Peak RSS C/B [95% CI] |
|---|---|---|
| Small-map signing | 1.0060 [0.9687, 1.0537] | 1.0048 [0.9979, 1.0119] |
| Large-map signing | 0.9884 [0.9588, 1.0153] | 0.9933 [0.9737, 1.0135] |
| Security library 4K | 0.9926 [0.9507, 1.0324] | 0.9987 [0.9920, 1.0057] |
| Security library 64K | 1.0024 [0.9812, 1.0225] | 0.9999 [0.9963, 1.0035] |
| TT repeated calls | 1.1726 [1.1470, 1.1972] | 0.2771 [0.2634, 0.2897] |
| JNA ARM64 | 0.9962 [0.9749, 1.0144] | 0.9972 [0.9825, 1.0126] |
| Telegram ARM32 | 0.9988 [0.9851, 1.0153] | 1.0044 [0.9958, 1.0112] |
| Telegram ARM64 | 1.0048 [0.9754, 1.0361] | 0.9985 [0.9924, 1.0050] |

TT wall speedup was 1.1674 [1.1444, 1.1908] and whole-process CPU speedup 1.1414
[1.1209, 1.1637]. Every pair improved operation time, CPU and RSS in both order
strata. Measured Java allocation was exactly unchanged, 5,096,000,312 bytes per
arm: the approximately 72.3% peak-RSS drop must not be described as lower Java
allocation. Earlier diagnostics traced repeated empty exit-block generation in
this workload; suppressing those blocks avoids native code-arena growth.

Other workloads do not establish speedup or equivalence. All their operation,
wall, process-CPU and RSS intervals include neutrality; negative point estimates
are retained above. Earlier different-path Telegram gains/regressions were not
reproduced under corrected path control.

## Cold results and limits

All eight cold wall-time intervals include neutrality. JNA RSS C/B is 1.0026
[0.9948, 1.0098], with no reproduction of the earlier large path-confounded cost.
Telegram ARM64 has a small exploratory RSS increase, 1.0075 [1.0002, 1.0174].
This is not a strict peak-memory bound or a guarantee against small regressions.
No universal startup improvement is claimed.

The demonstrated gain is workload-dependent and incremental, not a cumulative
upstream comparison and not the requested overall 20x improvement.
