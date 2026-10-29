# [unicorn2](https://github.com/unicorn-engine/unicorn) backend

ARM emulator backend based on [Unicorn Engine 2](https://github.com/unicorn-engine/unicorn) (upstream `2.1.4` plus the patches in `src/main/native/patches/`). Supports emulating ARM32/ARM64 native libraries on macOS, Linux and Windows.

## Supported Platforms

| Platform | Architecture | Output |
|----------|-------------|--------|
| macOS | ARM64 | `osx_arm64/libunicorn.dylib` |
| macOS | x86_64 | `osx_64/libunicorn.dylib` |
| Linux | x86_64 | `linux_64/libunicorn.so` |
| Linux | ARM64 | `linux_arm64/libunicorn.so` |
| Windows | x86_64 | `windows_64/unicorn.dll` |

## Prerequisites

### macOS Native Build

- Xcode Command Line Tools
- JDK (`JAVA_HOME` environment variable must be set)
- `pkg-config` (`brew install pkgconf`), required by unicorn's `qemu/configure`
- Unicorn source is cloned and patched automatically by `build.sh`: the upstream tag `2.1.4` is
  cloned into `~/git/unicorn-2.1.4` and `patches/*.patch` are applied. `build.sh` refuses to build a
  tree that is not exactly upstream `2.1.4` plus these patches.

#### Why the patch

`patches/0001-apple-jit-state-for-hooks-in-foreign-runtimes.patch` only changes behaviour on Apple
Silicon. Unicorn 2.1.x caches the per-thread `MAP_JIT` write protection, skips
`pthread_jit_write_protect_np()` when the cache already matches, and restores the caller's state only
when the outermost API call returns, but HotSpot toggles the same state on every JNI transition. A
`uc_*` call made from a Java hook (e.g. `munmap` in a syscall handler, or a nested `emu_start`) then
patches translated code with the thread still in execute mode and dies with `SIGBUS` in
`do_tb_phys_invalidate`; and once that is avoided, the nested call returns to Java in write mode and
the JVM faults on its own code. The patch always applies the requested state and hands the thread
back in its entry state on every nesting level. Drop it once upstream unicorn ships an equivalent fix.

### Docker Cross-Compilation (Linux / Windows)

- [Docker](https://www.docker.com/) (with `docker buildx` multi-platform support)

Docker clones the upstream unicorn tag from GitHub, applies `patches/` and compiles it inside the container.

## Build

All builds are performed via a single `build.sh` script located in `src/main/native/`:

```bash
cd backend/unicorn2/src/main/native

# Build all platforms
./build.sh all

# Build macOS only (ARM64 + x86_64)
./build.sh osx

# Build a single macOS target
./build.sh osx_arm64
./build.sh osx_64

# Build all Docker targets (Linux + Windows)
./build.sh docker

# Build a single Docker target
./build.sh linux_64
./build.sh linux_arm64
./build.sh windows_64

# Clean build (rebuild from scratch)
./build.sh --clean osx
```

Set the `UNICORN_HOME` environment variable to specify a custom unicorn source path (defaults to `~/git/unicorn-2.1.4`):

```bash
UNICORN_HOME=/path/to/unicorn ./build.sh osx_arm64
```

Build artifacts are placed in `src/main/resources/natives/<platform>/`.

## Scalar memory access

The JNI binding provides optional scalar-memory APIs for little-endian 1, 2,
4, and 8 byte values. They use the same Unicorn memory access checks as
`mem_read` and `mem_write`, without allocating a Java byte array for each value.
`Unicorn.hasScalarMemoryAccess()` reports native scalar-read support (API v1),
and `Unicorn.hasScalarMemoryWriteAccess()` reports scalar-write support (API v2).

The bundled Linux x86_64 library includes both optimizations. Older native
libraries, including other bundled platform libraries until rebuilt, remain
compatible: the Java binding detects the optional API version and falls back to
byte-array access for unsupported operations. Rebuilding a platform with the
commands above enables both scalar APIs on that platform. No instruction tracing
or memory validation is turned off by these optimizations. System-write tracing
and custom `onSystemWrite` observers continue receiving byte-array callbacks;
only the unobserved default path avoids the notification allocation.

## Bounded bulk JNI transfers

Bulk reads and writes of 1 through 4096 bytes use a per-call native stack
buffer with JNI array-region transfers instead of an acquired array-elements
buffer. Larger transfers retain the existing path. This avoids holding a pinned
Java array across Unicorn operations and keeps the same guest-memory checks,
callbacks and cache behavior. The rebuilt Linux x86_64 library includes this
path; other platform libraries need rebuilding to enable it.

The native bulk-read entry point rejects lengths outside `0..Integer.MAX_VALUE`
before allocating a Java array, preventing truncation of the destination size.

## Read-only host/API writes

The `0002` engine patch avoids rebuilding the guest memory topology for host
writes to already-readonly, ordinary root RAM mappings. It keeps full-range
validation, FlatView/RAMBlock clipping, and pre/post TLB and jump-cache flushes.
It does not grant guest write permission or automatically invalidate translated
blocks. Writable memory, MMIO, snapshot/COW mappings, and initially inconsistent
pointer-backed readonly state retain the legacy path.

This is a workload-specific optimization, not a general speed multiplier.
Read-only-write microbenchmarks benefit strongly as mapped-region counts grow;
complete application timings remain mixed, and individual writable-memory
microbenchmarks can be slightly slower. The bundled Linux x86_64 library has
been rebuilt with the patch. Other platforms must rebuild from upstream 2.1.4
plus the complete `patches/` set; they have not been runtime-validated here.

## Bounded private RAM backing reuse

The `0003` engine patch reuses up to 128 internally owned host RAM allocations
per emulator. Total admission is capped at 1 MiB, charging each payload plus one
host page for allocator/guard overhead. Non-host-page-sized allocations retain a
separate 64 KiB admission limit; individual payloads cannot exceed 64 KiB. Fixed
cache metadata is additional. These limits are not a universal bound on
platform-specific virtual-address reservation overhead.

The occupied entries form a dense prefix. Removal swaps the final entry into
the vacated slot, so a burst of same-sized pages can reuse its first matching
entry without scanning empty slots. Only exact-size buffers are reused, with
their original alignment restored and all payload bytes cleared before reuse.
Caller-owned `mem_map_ptr` buffers are never admitted. Every retained allocation
is released during emulator close, including when memory snapshots have held
unmapped regions until late teardown.

This does not keep freed guest mappings alive or cache RAMBlock/MemoryRegion
objects. Normal map/unmap validation, permissions, TB/TLB invalidation, partial
unmaps and snapshot/COW ownership remain in place. Public host reads/writes and
guest accesses to an unmapped guest address still fail.

Linux x86_64 paired fresh-process checks of this larger page pool versus the
previous eight-entry implementation found a 100-entry Map-to-JNI signing workload
about 24% faster in its operation phase and 23% faster end to end. A small-map
workload improved about 4%; peak RSS was essentially unchanged for both. Long
security-library encryption/decryption checks were near neutral to slightly
faster, with peak RSS changes around 1%. Fifteen paired cold-start repetitions
per workload were near neutral. Early sparse-cache experiments with slower
security-library samples were rejected rather than shipped.

This is not an overall 20x claim. ARM32/ARM64 dense ownership/accounting, zeroing,
mixed-size reuse, permissions, unmapped accesses, executable remapping,
caller-owned buffers, partial unmaps, memory snapshots and close/leak checks
passed, along with the Java regression checks. Other platform binaries have not
been rebuilt or runtime-validated here.

## Stable guest-store mapping reuse

The `0004` engine patch avoids a second MemoryRegion lookup within the same
ordinary guest store. It reuses the first result only while the access remains
stable: snapshots and registered write hooks disable reuse, and unmapped,
protected, copy-on-write and watchpoint paths invalidate that decision before
performing callbacks or recovery. MMIO and discarded writes retain their existing
paths. Atomic/probe callers still perform the original lookup.

This is a per-access local value, not a persistent mapping cache. No SDK names,
input values or expected outputs select the optimization. Guest permissions,
NOTDIRTY decisions, translated-code invalidation, hooks and snapshot semantics
are unchanged; no new heap allocation or retained-memory pool is introduced.

Seven alternating fresh-JVM pairs per workload on Linux x86_64 found the
security-library and Telegram workloads approximately 9-15% faster in the
operation phase, using the geometric mean of paired speed ratios. Small-map
and JNA workloads were near neutral. Paired peak-RSS geometric means changed by
less than approximately 1% in either direction. These measurements are not a
universal speed multiplier or an overall 20x claim.
Fifteen paired new-JVM starts per workload were near neutral end to end;
individual short startup/load subphases remained noisy. OS caches were not cleared.

ARM32/ARM64 upstream unit tests and Java regressions passed, with additional
private differential checks for scalar/unaligned/cross-page writes, permissions,
snapshot/COW, self-modifying guest code, MMIO and callback behavior. Remapping the
currently written page inside its own write callback remains an observed baseline
failure; this patch neither enables the fast path there nor repairs that case.
Only the Linux x86_64 binary was rebuilt and runtime-validated here. Other hosts
must rebuild from the complete patch set before using this optimization.

## Terminal page-dispatch compaction

The `0005` engine patch tracks the remaining radix depth during dispatch-tree
compaction, including already-compressed edges. A terminal node contains only
leaf section entries; unassigned holes are leaf entries too. Its full scan
cannot recurse or find a single child to collapse, so that scan is skipped.
Nonterminal compaction and every mapping/invalidation operation remain unchanged.
This is a general tree invariant, not an SDK, input or expected-result shortcut.
No persistent field, mapping cache or heap allocation is added.

Seven alternating fresh-JVM pairs per workload on Linux x86_64 found the two
Map-to-JNI signing workloads approximately 1.13x and 1.15x faster in their
operation phase, with every pair improving. This corresponds to approximately
12% and 13% less operation time, not an overall application speed multiplier.
Other workloads did not show a reliable benefit. An initial approximately 2.6%
Telegram64 throughput decrease was not reproduced in ten additional pairs.
Keeping all original and additional measurements, TT and Telegram64 were near
neutral, while JNA64 remained approximately 2.4% lower in throughput. Its wide
exploratory interval includes both neutrality and a small regression; this is
not proof that all workloads are unaffected. Follow-up workloads were selected
after inspecting the first results, and no original measurements were discarded.

Paired peak-RSS geometric means were approximately unchanged, within about 1%
after combining those follow-ups; TT peak RSS remained noisy and does not
establish a tight memory bound. Java allocation totals were essentially
unchanged. Fifteen paired fresh-JVM starts per workload did not establish a
broad cold-start benefit. OS caches were not cleared. These are incremental,
workload-dependent results, not the requested overall 20x improvement.

Private validation included byte-identical old/new trees across randomized and
boundary mappings, repeated compaction, address/undefined-behavior sanitizers,
ARM32/ARM64 upstream unit tests, guest-store and callback checks, mapping
ownership/permissions, 200 memory-snapshot restore/close cycles, and Java
regressions. Leak detection was unavailable in the sanitizer environment; no
leak-freedom claim is made. The known baseline remap-inside-write-callback
failure remains outside this optimization. Only the Linux x86_64 binary was
rebuilt and runtime-validated; other hosts require a rebuild and validation.

## Validated first-store section reuse

The `0006` engine patch records an existing dispatch-section index alongside a
TLB entry, only for ordinary RAM sections covering the complete physical page
in the same address-space dispatch. A guest store can use that index instead of
its first mapping query only while the original write TLB tag is valid and
matching, with no snapshot or registered write hook. The index has no independent
lifetime: normal invalidation, refill and whole-entry victim swaps remain in
force. Invalid or ineligible entries retain the original query. Callback and
recovery paths, permissions, NOTDIRTY/SMC, MMIO and COW behavior are unchanged.
This is a general mapping invariant, with no SDK names or expected-result cache.

The field uses existing alignment padding in the tested Linux x86_64 builds:
`CPUIOTLBEntry` remains 16 bytes for both ARM32 and ARM64 guests. No additional
heap allocation or retained MemoryRegion object is introduced. The optimization
is disabled on 32-bit hosts; other host platforms have not been runtime-tested.

Relative to commit `d0b9577`, seven alternating fresh-JVM pairs for each of eight
workloads found security-library and Telegram operation phases approximately
7-10% faster and TT approximately 3% faster. Small-map signing was near neutral;
large-map signing and JNA had negative throughput point estimates of about 0.7%
and 0.8%. Their exploratory intervals include neutrality and small regressions,
so this is not a claim that every workload is unaffected. All original pairs
were retained; the earlier short screening runs are not included in these figures.

Paired peak-RSS geometric means ranged from about -2.5% to +1.3%. The two
security-library workloads increased about 0.7% and 0.9%; TT was noisy, with its
exploratory ratio interval spanning roughly -8% to +7%. Unchanged entry size does
not imply zero process-memory cost or a strict peak-memory bound. Fifteen paired
fresh-JVM starts per workload did not establish a broad cold-start improvement;
OS caches were not cleared. Intervals are exploratory, single-workload bootstrap
intervals without multiple-comparison correction, on one host configuration.
These are incremental results, not an overall 20x speedup.

ARM32/ARM64 upstream units, Java regressions and private differential checks
passed. Additional checks covered nonidentity virtual mappings above 4 GiB,
aliases, read-driven victim swaps followed by stores, section renumbering after
topology changes, permissions/hooks, explicit TLB flushes, split mappings and
memory snapshots. The complete upstream-plus-patches source sequence was also
reproduced. IOMMU/subpage paths are conservatively excluded when the eligibility
conditions do not hold, but were not separately runtime-tested. The previously
noted write-callback remapping failure remains unchanged. Only the bundled
Linux x86_64 library was rebuilt and runtime-validated for this patch.

## Validated warm ARM exit handling

Patch `0007` avoids repeatedly generating eligible empty ARM32/ARM64 exit blocks.
It reuses the existing WFI helper only when code translations are already valid
and special execution modes/hooks are absent; otherwise it retains translation.
No persistent cache, SDK check or expected-result substitution is added.

Corrected identical-runtime-path comparisons against `67df098` found repeated
TT calls approximately 17.3% faster with approximately 72.3% lower peak RSS;
measured Java allocation was unchanged. Seven other workloads did not establish
a speedup or a significant sustained regression, which is not proof of
nonregression. Cold tests found no broad startup improvement and a small
exploratory Telegram ARM64 RSS increase. Earlier different-path JNA results were
confounded by the benchmark paths, as confirmed with identical-binary A/A tests.
See [measurement and validation details](../../docs/performance/WARM_EXIT_RESULTS.md)
for intervals, limitations, preserved adverse observations and reproduction.
Only Linux x86_64 was rebuilt and tested. This is not an overall 20x speedup.

## Validated direct cached-RAM section lookup

Patch `0008` uses the current global physical dispatch for an already-validated
RAM section index at the existing guarded store call site. It removes redundant
attribute dispatch, without broadening eligibility, retaining raw pointers,
adding fields or skipping permission/MMU checks. Generic I/O lookup is unchanged.

Seven identical-path pairs per workload against `462a85d` found approximately
2–5% incremental operation/wall improvements in six of eight workloads; two were
inconclusive. TT peak RSS increased approximately 2.05 MiB / 1.7% consistently,
while other long-workload RSS intervals included neutrality. This is a small
memory tradeoff, not a zero-growth guarantee. Cold tests show no broad startup
gain. See [full validation and limits](../../docs/performance/DIRECT_RAM_SECTION_RESULTS.md).
Only Linux x86_64 was rebuilt/runtime-tested; overall 20x is not achieved.

## Guarded AArch64 NOTDIRTY byte stores

Patch `0009` narrows a common AArch64 byte-store helper path while retaining the
complete dirty tracking and self-modifying-code invalidation call. Other flags,
hooks, snapshots, permissions and misses keep the original slow path. ARM32's
cputlb machine-code text is unchanged; no SDK check or persistent cache is added.

Seven independent same-path pairs per workload against `e737a30d` found Telegram
ARM64 work time about 10.2% lower and process wall about 9.7% lower; other long
workloads did not establish changes. This is an ARM64 optimization with a
concentrated measured benefit, not universal acceleration. Long peak RSS was
near-neutral; a separate cold confirmation observed TT RSS about +350 KiB / 0.4%.
Cold-start acceleration and strict nonregression are not established. See
[full results and adverse observations](../../docs/performance/AARCH64_BYTE_STORE_RESULTS.md).
Only Linux x86_64 was rebuilt and runtime-tested. Overall 20x remains unachieved.


## Guarded ARM32 word and AArch64 doubleword stores

Patch `0010` adds narrow little-endian 4-byte ARM32 and 8-byte AArch64 NOTDIRTY
store paths on 64-bit hosts, retaining alignment, mapping/permission guards and
complete dirty/SMC handling. Other cases retain the original fallback; no new
cache or per-engine field is added.

Seven same-path pairs per workload against `cae8988` found equal-case long work
about 5.3% lower and process wall about 4.8% lower, concentrated in security-library
and Telegram workloads. Aggregate peak RSS was near-neutral. Independent targeted
confirmation did not consistently reproduce initial map-memory/load regressions,
but observed JNA startup approximately 5 ms higher on average, and cold whole-process
intervals still allow small regressions. This is not a universal startup improvement or a
strict nonregression guarantee. See [full results and limits](../../docs/performance/GUARDED_WIDE_STORE_RESULTS.md).
Only Linux x86_64 was rebuilt and runtime-tested. Overall 20x remains unachieved.
