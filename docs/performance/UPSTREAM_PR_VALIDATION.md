# Upstream PR scope and validation

## Scope

This branch is based on upstream `2ede14d50c869bf9201b89c3a9ee545ffe089968`.
Its production files are byte-for-byte identical to the tested synchronization
merge tree `bf76a5569f4e223944e5a08ff62a4a6a5f2c3c4c` in the fork.

It contains accepted Java/JNI, ELF-loading and guarded Unicorn2 optimizations.
It does not include held snapshot/identity experiments, exit-request guards,
DC ZVA batching, indexed services, bounded-temp lookup, or other experimental
implementations. The branch starts directly from upstream rather than carrying
private experiment history. Benchmark/sample code, timing scripts and raw logs
are not added by this PR; existing upstream tests remain unchanged.

The updated native artifact is Linux x86_64 only. Native patches and build notes
are included. Other platforms have not been rebuilt or newly validated here.

## Fresh synchronization checks

On Linux x86_64 with JDK 8:

- All reactor modules completed `test-compile`, with test compilation explicitly
  enabled. The first invocation inherited a test-skip setting; that invocation
  was not counted as test compilation.
- A direct JUnitCore run, isolated by class and using each module's working
  directory, passed 66 tests in 29 fully passing classes.
  This count is for the tested merge tree: 62 tests in 27 classes remain in
  this PR; four additional checks in IntArrayNativeTest and IntArrayTest were
  run from fork-local test sources that are intentionally excluded from the PR.
- All 11 new upstream test classes passed: ImportedSymbolTest, PackedSoLoadTest,
  PrctlTest, ArrayInstanceOfTest, BitmapTest, CharArrayTest, FloatArrayRegionTest,
  JniBasicsTest, ApkSigningBlockParserTest, ElfParserTest and ProcFdTest.
- Eight representative workload smokes passed with the actual loaded-native
  SHA256 checked: small/large-map signing, SG 4K/64K, TT, JNA64 and Telegram32/64.
  These are output/completion checks, not a fresh performance comparison.
- ARM32 and ARM64 JNI table review retained all 229 slot-to-handler bindings and
  the single little-endian table write. Both sides of the four overlapping
  source-file changes were preserved by the upstream merge.
- The accepted native artifact was unchanged during synchronization:
  `27fcc8f9c7c6bf3708fd5fc4943941d008ffa493bde49283dff80e9689d32dfa`.

The complete Maven `test` goal did **not** pass: Surefire 2.12.4 was absent from
this environment's cache and Maven Central DNS was unavailable. JUnitCore was
used explicitly instead; this is not a claim that the full Maven/CI suite is green.

Initial manual runs used the repository root as working directory. Relative
fixture failures in PropertiesTest, MachOTest, ImportedSymbolTest and
PackedSoLoadTest were corrected by using their module directories, after which
those classes passed. Their initial logs were retained.

## Remaining validation limitations

The following failing classes were also run against the pre-merge accepted
checkpoint `ab9400b124b699f56518f87b347777866f25ce4b`, where their failure modes
were reproduced. They are not counted as passed:

- Hypervisor HexTest/VCpuTest: native symbols unavailable on this host.
- KvmTest: the required KVM backend/device is unavailable.
- AndroidNativeEmuTest: legacy Unicorn native loading fails; this differs from
  the successfully tested Unicorn2 path.
- ClassDumpTest: its selected dylib does not match the requested 32-bit format.
- ClassDump64Test: native abort in the Dynarmic fallback/debugger path. The cause
  remains unresolved; matching baseline failure does not make this a passing test.
- Substrate64Test: its relative fixture path is unavailable with the module
  working directory. An earlier root-directory attempt also did not complete
  within its timeout; that observation is retained separately.

MountTest has no JUnit test method and was initially misclassified by the manual
enumerator. It is not an executed assertion test. No new platform support,
all-workload correctness guarantee or universal non-regression is claimed.

## Historical performance evidence

The historical original-upstream comparison is specifically
`2ba8156` versus `cae8988`, not a new benchmark of this synchronized PR.
It measured equal-family work at 1.460x and whole-process wall at 1.438x across
eight workloads, with peak-RSS ratio 0.825. Individual workloads and cold phases
vary; some cold phases regressed and small-map/TT cold peak RSS rose about 1.5%.

The later accepted guarded-wide-store increment was measured separately against
`cae8988`, with roughly 5.3% lower aggregate long-work time and near-neutral
aggregate RSS. Its cold-stage tradeoffs and uncertainty remain documented.
Do not multiply these separate experiments into a new cumulative speedup.

See `ORIGINAL_UPSTREAM_COMPARISON.md`, `WARM_EXIT_RESULTS.md`,
`DIRECT_RAM_SECTION_RESULTS.md`, `AARCH64_BYTE_STORE_RESULTS.md` and
`GUARDED_WIDE_STORE_RESULTS.md` for exact versions, methodology and adverse
observations. No general 20x result or universal startup/memory improvement is
claimed.
