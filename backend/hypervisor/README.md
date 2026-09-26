# Apple Silicon Hypervisor backend

ARM64 emulator backend using the macOS Hypervisor.framework. Allows you to emulate Android and iOS ARM64 native libraries on Apple Silicon at near-native speed.

## Supported Platforms

| Platform | Architecture | Output |
|----------|-------------|--------|
| macOS | ARM64 (Apple Silicon) | `osx_arm64/libhypervisor.dylib` |

## Prerequisites

- Apple Silicon Mac (M1/M2/M3/M4)
- Xcode Command Line Tools
- JDK (`JAVA_HOME` environment variable must be set)

## Sign the Java Binary

The Hypervisor.framework requires a special entitlement. Sign the `java` binary before running:

```bash
cd backend/hypervisor/assets
sudo ./ldid -M -Shypervisor.entitlements "$JAVA_HOME"/bin/java
```

## Build

```bash
cd backend/hypervisor/src/main/native/hypervisor
./build.sh
```

Build artifacts are placed in `src/main/resources/natives/osx_arm64/`.

The dylib is built with `-mmacosx-version-min=11.0`; the macOS-specific code paths below are selected at runtime with `@available`, so one binary covers every supported release.

## macOS 27

macOS 27 changed the private layout of Hypervisor.framework (`Hv::Vcpu` and the vCPU context buffer). Builds older than commit `a1cfee9e` do not work on it.

### Symptoms with an older build

- `java.lang.IllegalStateException: Illegal JNI version: 0xffffffff` from `callJNI_OnLoad`
- Warnings such as `Read memory failed: address=0x..., size=0` followed by `HypervisorException: ret=1` in almost every library initializer
- With debug logging on `HypervisorBackend64`: `syndrome=0x92000035 ... ec=0x24`, `dfsc=0x35`

The guest runs with the stage-1 MMU off and relies on `HCR_EL2.DC=1` to make memory Normal. Older builds wrote that bit through a fixed offset inside `Hv::Vcpu`, which on macOS 27 lands in a different field, so memory stays Device and every `LDXR`/`STXR` faults (DFSC `0x35`, unsupported exclusive access). Update to a build that contains the fix, or rebuild the dylib.

### How the backend works on macOS 27+

No fixed offsets into framework-private structures are used:

| | macOS 27+ | macOS 15.0 – 26 | Before macOS 15 |
|---|---|---|---|
| `HCR_EL2.DC` | `_hv_vcpu_get/set_control_field` (exported, indexed by field number) | trap-override field inside `Hv::Vcpu` (fixed offset) | `HCR_EL2` slot in the `_vcpus` array (fixed offset) |
| `context_save` / `context_restore` | public register API | raw copy of the vCPU context buffer (0x1000 bytes) | raw copy (0x7C0 bytes) |
| `_vcpus` symbol lookup | not used | required, aborts with `Verify _vcpus failed` on mismatch | required |

On macOS 27+ a saved context holds only per-thread state: X0–X30, PC, CPSR, FPCR, FPSR, ELR_EL1, SPSR_EL1, Q0–Q31, plus SP_EL0, CPACR_EL1, TPIDR_EL0 and TPIDRRO_EL0. vCPU-wide state is left alone: HCR_EL2 and the other control fields, VBAR/SCTLR, MDSCR (single step), timers, and the hardware breakpoint/watchpoint registers. As a result, restoring a context no longer drops hardware breakpoints or watchpoints installed after it was saved. The raw-copy path used on earlier releases also copies the debug registers, so it rolls them back.

`_hv_vcpu_get/set_control_field` are weak imports. If a future release stops exporting them, the dylib still loads, and the backend aborts on the first vCPU with:

```
Hypervisor.framework does not export _hv_vcpu_get/set_control_field: get=0x0, set=0x0
```

Please report the macOS build number (`sw_vers`) when you hit this.
