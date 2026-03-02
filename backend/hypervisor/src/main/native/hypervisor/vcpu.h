#pragma once
#include <Hypervisor/Hypervisor.h>

#include <cstdio>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>

// Diagnostics — must not be disabled by NDEBUG
#define HYP_ASSERT_SUCCESS(ret) do { \
    hv_return_t _ret = (hv_return_t) (ret); \
    if (__builtin_expect(_ret != HV_SUCCESS, 0)) { \
        fprintf(stderr, "HYP_ASSERT_SUCCESS failed: %d at %s:%d\n", (int)_ret, __FILE__, __LINE__); \
        abort(); \
    } \
} while(0)
#define HV_REG_SP HV_SYS_REG_SP_EL0

// vcpu_context: mirrors the Hypervisor framework's internal vCPU context buffer.
//
// Offsets listed are for the macOS 15+ layout (sizeof = 0x7F0).
// Pre-macOS 15: the 6 NV2 fields (0x448-0x470) don't exist, so fields after
// CNTKCTL_EL1 are 0x30 bytes earlier (sizeof = 0x7C0).
//
// [VNCR] marks fields that on macOS 15+ are managed via the VNCR page
// (context+0x1000) through VcpuStateManager, NOT written to these context
// buffer offsets. The API (hv_vcpu_get/set_sys_reg) is VNCR-aware and
// reads/writes the correct location transparently.
// The slots at the old offsets are stale on macOS 15+ and should not be
// read directly from the context buffer.
//
// PAC key fields are stored in the Vcpu C++ object (this+24..this+104),
// not in the context buffer. They appear here for layout completeness
// but are not maintained by the framework at these offsets.
typedef struct vcpu_context {
  uint64_t magic;                        // 0x000
  uint64_t HV_REG_X0;                   // 0x008
  uint64_t HV_REG_X1;                   // 0x010
  uint64_t HV_REG_X2;                   // 0x018
  uint64_t HV_REG_X3;                   // 0x020
  uint64_t HV_REG_X4;                   // 0x028
  uint64_t HV_REG_X5;                   // 0x030
  uint64_t HV_REG_X6;                   // 0x038
  uint64_t HV_REG_X7;                   // 0x040
  uint64_t HV_REG_X8;                   // 0x048
  uint64_t HV_REG_X9;                   // 0x050
  uint64_t HV_REG_X10;                  // 0x058
  uint64_t HV_REG_X11;                  // 0x060
  uint64_t HV_REG_X12;                  // 0x068
  uint64_t HV_REG_X13;                  // 0x070
  uint64_t HV_REG_X14;                  // 0x078
  uint64_t HV_REG_X15;                  // 0x080
  uint64_t HV_REG_X16;                  // 0x088
  uint64_t HV_REG_X17;                  // 0x090
  uint64_t HV_REG_X18;                  // 0x098
  uint64_t HV_REG_X19;                  // 0x0A0
  uint64_t HV_REG_X20;                  // 0x0A8
  uint64_t HV_REG_X21;                  // 0x0B0
  uint64_t HV_REG_X22;                  // 0x0B8
  uint64_t HV_REG_X23;                  // 0x0C0
  uint64_t HV_REG_X24;                  // 0x0C8
  uint64_t HV_REG_X25;                  // 0x0D0
  uint64_t HV_REG_X26;                  // 0x0D8
  uint64_t HV_REG_X27;                  // 0x0E0
  uint64_t HV_REG_X28;                  // 0x0E8
  uint64_t HV_REG_X29;                  // 0x0F0  HV_REG_FP
  uint64_t HV_REG_X30;                  // 0x0F8  HV_REG_LR
  uint64_t unknown0x100;                 // 0x100
  uint64_t HV_REG_PC;                   // 0x108
  uint64_t HV_REG_CPSR;                 // 0x110

  char _pad1[0x28];                      // 0x118-0x13F
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q0;  // 0x140  (16 bytes each)
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q1;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q2;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q3;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q4;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q5;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q6;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q7;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q8;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q9;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q10;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q11;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q12;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q13;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q14;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q15;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q16;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q17;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q18;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q19;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q20;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q21;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q22;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q23;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q24;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q25;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q26;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q27;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q28;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q29;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q30;
  hv_simd_fp_uchar16_t HV_SIMD_FP_REG_Q31;   // 0x330

  uint32_t HV_REG_FPSR;                 // 0x340  DWORD
  uint32_t HV_REG_FPCR;                 // 0x344  DWORD
  uint64_t _pad_fpcr;                    // 0x348
  uint64_t HV_SYS_REG_MDSCR_EL1;        // 0x350  [VNCR]
  uint64_t HV_SYS_REG_TPIDR_EL1;        // 0x358
  uint64_t HV_SYS_REG_TPIDR_EL0;        // 0x360
  uint64_t HV_SYS_REG_TPIDRRO_EL0;      // 0x368
  uint64_t HV_SYS_REG_SP_EL0;           // 0x370
  uint64_t HV_SYS_REG_SP_EL1;           // 0x378  [VNCR]
  uint64_t HV_SYS_REG_PAR_EL1;          // 0x380
  uint64_t HV_SYS_REG_CSSELR_EL1;       // 0x388
  uint64_t ext_reg;                      // 0x390  _hv_vcpu_get_ext_reg
  uint64_t unknown0x398_0xF795;          // 0x398
  uint64_t HV_SYS_REG_TTBR0_EL1;        // 0x3A0  [VNCR]
  uint64_t HV_SYS_REG_TTBR1_EL1;        // 0x3A8  [VNCR]
  uint64_t HV_SYS_REG_TCR_EL1;          // 0x3B0  [VNCR]
  uint64_t HV_SYS_REG_ELR_EL1;          // 0x3B8  [VNCR]
  uint64_t HV_SYS_REG_FAR_EL1;          // 0x3C0  [VNCR]
  uint64_t HV_SYS_REG_ESR_EL1;          // 0x3C8  [VNCR]
  char _pad3[0x10];                      // 0x3D0-0x3DF
  uint64_t HV_SYS_REG_VBAR_EL1;         // 0x3E0  [VNCR]
  uint64_t HV_SYS_REG_CNTV_CVAL_EL0;    // 0x3E8  [VNCR]
  uint64_t HV_SYS_REG_MAIR_EL1;         // 0x3F0  [VNCR]
  uint64_t HV_SYS_REG_AMAIR_EL1;        // 0x3F8
  uint64_t HV_SYS_REG_SCTLR_EL1;        // 0x400  [VNCR]
  uint64_t HV_SYS_REG_CPACR_EL1;        // 0x408  [VNCR]
  uint64_t HV_SYS_REG_SPSR_EL1;         // 0x410  [VNCR]
  uint64_t HV_SYS_REG_AFSR0_EL1;        // 0x418
  uint64_t HV_SYS_REG_AFSR1_EL1;        // 0x420
  uint64_t HV_SYS_REG_CONTEXTIDR_EL1;   // 0x428  [VNCR]
  uint64_t HV_SYS_REG_CNTV_CTL_EL0;     // 0x430  [VNCR]
  uint64_t unknown0x438;                 // 0x438
  uint64_t HV_SYS_REG_CNTKCTL_EL1;      // 0x440
  // macOS 15+ inserts 6 NV2 fields here (0x30 bytes), shifting all subsequent offsets by +0x30
  uint64_t _nv2_field0;                  // 0x448 (macOS 15+ only)
  uint64_t _nv2_field1;                  // 0x450
  uint64_t _nv2_field2;                  // 0x458
  uint64_t _nv2_field3;                  // 0x460
  uint64_t _nv2_field4;                  // 0x468
  uint64_t _nv2_field5;                  // 0x470
  // --- offsets below: macOS 15+ / pre-15 ---
  uint64_t HV_SYS_REG_DBGBVR0_EL1;      // 0x478 / 0x448
  uint64_t HV_SYS_REG_DBGBCR0_EL1;
  uint64_t HV_SYS_REG_DBGBVR1_EL1;
  uint64_t HV_SYS_REG_DBGBCR1_EL1;
  uint64_t HV_SYS_REG_DBGBVR2_EL1;
  uint64_t HV_SYS_REG_DBGBCR2_EL1;
  uint64_t HV_SYS_REG_DBGBVR3_EL1;
  uint64_t HV_SYS_REG_DBGBCR3_EL1;
  uint64_t HV_SYS_REG_DBGBVR4_EL1;
  uint64_t HV_SYS_REG_DBGBCR4_EL1;
  uint64_t HV_SYS_REG_DBGBVR5_EL1;
  uint64_t HV_SYS_REG_DBGBCR5_EL1;
  uint64_t HV_SYS_REG_DBGBVR6_EL1;
  uint64_t HV_SYS_REG_DBGBCR6_EL1;
  uint64_t HV_SYS_REG_DBGBVR7_EL1;
  uint64_t HV_SYS_REG_DBGBCR7_EL1;
  uint64_t HV_SYS_REG_DBGBVR8_EL1;
  uint64_t HV_SYS_REG_DBGBCR8_EL1;
  uint64_t HV_SYS_REG_DBGBVR9_EL1;
  uint64_t HV_SYS_REG_DBGBCR9_EL1;
  uint64_t HV_SYS_REG_DBGBVR10_EL1;
  uint64_t HV_SYS_REG_DBGBCR10_EL1;
  uint64_t HV_SYS_REG_DBGBVR11_EL1;
  uint64_t HV_SYS_REG_DBGBCR11_EL1;
  uint64_t HV_SYS_REG_DBGBVR12_EL1;
  uint64_t HV_SYS_REG_DBGBCR12_EL1;
  uint64_t HV_SYS_REG_DBGBVR13_EL1;
  uint64_t HV_SYS_REG_DBGBCR13_EL1;
  uint64_t HV_SYS_REG_DBGBVR14_EL1;
  uint64_t HV_SYS_REG_DBGBCR14_EL1;
  uint64_t HV_SYS_REG_DBGBVR15_EL1;
  uint64_t HV_SYS_REG_DBGBCR15_EL1;
  uint64_t HV_SYS_REG_DBGWVR0_EL1;
  uint64_t HV_SYS_REG_DBGWCR0_EL1;
  uint64_t HV_SYS_REG_DBGWVR1_EL1;
  uint64_t HV_SYS_REG_DBGWCR1_EL1;
  uint64_t HV_SYS_REG_DBGWVR2_EL1;
  uint64_t HV_SYS_REG_DBGWCR2_EL1;
  uint64_t HV_SYS_REG_DBGWVR3_EL1;
  uint64_t HV_SYS_REG_DBGWCR3_EL1;
  uint64_t HV_SYS_REG_DBGWVR4_EL1;
  uint64_t HV_SYS_REG_DBGWCR4_EL1;
  uint64_t HV_SYS_REG_DBGWVR5_EL1;
  uint64_t HV_SYS_REG_DBGWCR5_EL1;
  uint64_t HV_SYS_REG_DBGWVR6_EL1;
  uint64_t HV_SYS_REG_DBGWCR6_EL1;
  uint64_t HV_SYS_REG_DBGWVR7_EL1;
  uint64_t HV_SYS_REG_DBGWCR7_EL1;
  uint64_t HV_SYS_REG_DBGWVR8_EL1;
  uint64_t HV_SYS_REG_DBGWCR8_EL1;
  uint64_t HV_SYS_REG_DBGWVR9_EL1;
  uint64_t HV_SYS_REG_DBGWCR9_EL1;
  uint64_t HV_SYS_REG_DBGWVR10_EL1;
  uint64_t HV_SYS_REG_DBGWCR10_EL1;
  uint64_t HV_SYS_REG_DBGWVR11_EL1;
  uint64_t HV_SYS_REG_DBGWCR11_EL1;
  uint64_t HV_SYS_REG_DBGWVR12_EL1;
  uint64_t HV_SYS_REG_DBGWCR12_EL1;
  uint64_t HV_SYS_REG_DBGWVR13_EL1;
  uint64_t HV_SYS_REG_DBGWCR13_EL1;
  uint64_t HV_SYS_REG_DBGWVR14_EL1;
  uint64_t HV_SYS_REG_DBGWCR14_EL1;
  uint64_t HV_SYS_REG_DBGWVR15_EL1;
  uint64_t HV_SYS_REG_DBGWCR15_EL1;      // 0x670 / 0x640
  uint64_t HV_SYS_REG_MDCCINT_EL1;        // 0x678 / 0x648
  char _pad4[0x18];                        // 0x680 / 0x650
  uint64_t control_field_0;               // 0x698 / 0x668  HCR_EL2 via _hv_vcpu_set_control_field(0)
  uint64_t control_field_6;               // 0x6A0 / 0x670
  uint64_t control_field_1;               // 0x6A8 / 0x678
  uint64_t HV_SYS_REG_MDCR_EL2;          // 0x6B0 / 0x680  control_field_2
  uint64_t HV_SYS_REG_MPIDR_EL1;         // 0x6B8 / 0x688  control_field_3
  uint64_t HV_SYS_REG_MIDR_EL1;          // 0x6C0 / 0x690  control_field_5
  uint64_t HV_SYS_REG_CNTVOFF_EL2;       // 0x6C8 / 0x698  control_field_4
  uint64_t unknown0x6a0;                  // 0x6D0 / 0x6A0
  uint64_t control_field_12;              // 0x6D8 / 0x6A8
  uint64_t control_field_13;              // 0x6E0 / 0x6B0
  uint64_t control_field_14;              // 0x6E8 / 0x6B8
  uint64_t control_field_15;              // 0x6F0 / 0x6C0
  uint64_t control_field_16;              // 0x6F8 / 0x6C8
  uint64_t vtimer_mask_reg;               // 0x700 / 0x6D0  hv_vcpu_set_vtimer_mask
  uint64_t control_field_7;               // 0x708 / 0x6D8
  uint64_t control_field_8;               // 0x710 / 0x6E0
  uint64_t control_field_9;               // 0x718 / 0x6E8
  uint64_t control_field_10;              // 0x720 / 0x6F0
  uint64_t control_field_11;              // 0x728 / 0x6F8
  uint64_t unknown0x700;                  // 0x730 / 0x700  trap debug related
  uint64_t exec_time;                     // 0x738 / 0x708  cumulative execution time (ns)
  char _pad5[0x60];                       // 0x740 / 0x710  (dirty flags at context+0x780 are within this region)
  uint64_t HV_SYS_REG_APGAKEYHI_EL1;     // 0x7A0 / 0x770  (PAC: stored in Vcpu object, not here)
  uint64_t HV_SYS_REG_APGAKEYLO_EL1;     // 0x7A8 / 0x778
  uint64_t HV_SYS_REG_APIAKEYHI_EL1;     // 0x7B0 / 0x780
  uint64_t HV_SYS_REG_APIAKEYLO_EL1;     // 0x7B8 / 0x788
  uint64_t HV_SYS_REG_APIBKEYHI_EL1;     // 0x7C0 / 0x790
  uint64_t HV_SYS_REG_APIBKEYLO_EL1;     // 0x7C8 / 0x798
  uint64_t HV_SYS_REG_APDAKEYHI_EL1;     // 0x7D0 / 0x7A0
  uint64_t HV_SYS_REG_APDAKEYLO_EL1;     // 0x7D8 / 0x7A8
  uint64_t HV_SYS_REG_APDBKEYHI_EL1;     // 0x7E0 / 0x7B0
  uint64_t HV_SYS_REG_APDBKEYLO_EL1;     // 0x7E8 / 0x7B8  (end of struct)
} *t_vcpu_context;

// macOS 15+ added 6 fields (0x30 bytes) between CNTKCTL_EL1 and DBGBVR0_EL1.
// sizeof(struct vcpu_context) = 0x7F0 (macOS 15+ named fields only).
//
// The actual kernel context buffer extends well beyond sizeof(vcpu_context):
//   0x000-0x7EF  named registers (struct vcpu_context)
//   0x7F0-0xA18  private/internal registers (NV2, PMU, written by framework)
//   0xA20-0xFFF  reserved / unknown internal state
//   0x1000+      VNCR page (managed via hv_vcpu_get/set_sys_reg API)
//
// For single-thread context switching on the same vCPU, we must save/restore
// up to 0x1000 to preserve internal state modified during hv_vcpu_run.
//
// VNCR note: on macOS 15+, [VNCR]-marked registers (SCTLR, TTBR0/1, TCR,
// ELR, SPSR, ESR, FAR, VBAR, MAIR, CPACR, CONTEXTIDR, CNTV_*, MDSCR,
// SP_EL1) live at context+0x1000 offsets and are NOT in our memcpy range.
// This is safe for unidbg because:
//   - page table / system regs (SCTLR, TTBR, TCR, VBAR, MAIR, MDSCR) are
//     one-time init and identical across contexts on the same vCPU
//   - CPACR is stored separately in hypervisor->cpacr and set via API
//   - ELR/SPSR are set via API in emu_start / exception handling
//   - ESR/FAR are read-only (set by hardware on exception entry)
inline size_t vcpu_context_size() {
  if (@available(macOS 15.0.0, *)) {
    return 0x1000;
  }
  return sizeof(struct vcpu_context) - 0x30; // 0x7C0 (pre-macOS 15)
}

typedef struct vcpus {
  t_vcpu_context context;
  uint64_t HV_SYS_REG_ID_AA64DFR0_EL1;
  uint64_t HV_SYS_REG_ID_AA64DFR1_EL1;
  uint64_t HV_SYS_REG_ID_AA64ISAR0_EL1;
  uint64_t HV_SYS_REG_ID_AA64ISAR1_EL1;
  uint64_t HV_SYS_REG_ID_AA64MMFR0_EL1;
  uint64_t HV_SYS_REG_ID_AA64MMFR1_EL1;
  uint64_t HV_SYS_REG_ID_AA64MMFR2_EL1;
  uint64_t HV_SYS_REG_ID_AA64PFR0_EL1;
  uint64_t HV_SYS_REG_ID_AA64PFR1_EL1;
  char _pad1[0x98];
  uint64_t HV_SYS_REG_HCR_EL2;
  char _pad2[0x28];
} *t_vcpus;

typedef struct vcpus_v1351 {
  t_vcpu_context context;
  uint64_t HV_SYS_REG_ID_AA64DFR0_EL1;
  uint64_t HV_SYS_REG_ID_AA64DFR1_EL1;
  uint64_t HV_SYS_REG_ID_AA64ISAR0_EL1;
  uint64_t HV_SYS_REG_ID_AA64ISAR1_EL1;
  uint64_t HV_SYS_REG_ID_AA64MMFR0_EL1;
  uint64_t HV_SYS_REG_ID_AA64MMFR1_EL1;
  uint64_t HV_SYS_REG_ID_AA64MMFR2_EL1;
  uint64_t HV_SYS_REG_ID_AA64PFR0_EL1;
  uint64_t HV_SYS_REG_ID_AA64PFR1_EL1;
  char _pad1[0x98];
  uint64_t vcpu_config; // since 13.5.1
  uint64_t HV_SYS_REG_HCR_EL2;
  char _pad2[0x28];
} *t_vcpus_v1351;

// macOS 15.0+: _vcpus[] is an array of pointers to Hv::Vcpu C++ objects.
// This struct overlays the Hv::Vcpu object starting from its base address.
typedef struct vcpus_v1500 {
  void *vtable;                                   // 0x00  Hv::Vcpu vtable
  void *delegate;                                 // 0x08  VcpuStateManager::Delegate
  t_vcpu_context context;                         // 0x10  arm_guest_context_t*
  uint64_t HV_SYS_REG_ID_AA64DFR0_EL1;           // 0x18  feature_regs
  uint64_t HV_SYS_REG_ID_AA64DFR1_EL1;           // 0x20
  uint64_t HV_SYS_REG_ID_AA64ISAR0_EL1;          // 0x28
  uint64_t HV_SYS_REG_ID_AA64ISAR1_EL1;          // 0x30
  uint64_t HV_SYS_REG_ID_AA64MMFR0_EL1;          // 0x38
  uint64_t HV_SYS_REG_ID_AA64MMFR1_EL1;          // 0x40
  uint64_t HV_SYS_REG_ID_AA64MMFR2_EL1;          // 0x48
  uint64_t HV_SYS_REG_ID_AA64PFR0_EL1;           // 0x50
  uint64_t HV_SYS_REG_ID_AA64PFR1_EL1;           // 0x58
  char _pad1[0x98];                               // 0x60  remaining feature_regs
  uint64_t vcpu_config;                           // 0xF8  CfPtr<hv_vcpu_config_s>
  uint64_t hcr_el2_trap_override;                 // 0x100 ORed into control_field_0 (HCR_EL2) before hv_vcpu_run
} *t_vcpus_v1500;

// macOS 15.2+: same as vcpus_v1500 but with 2 additional fields before trap_override.
typedef struct vcpus_v1520 {
  void *vtable;                                   // 0x00  Hv::Vcpu vtable
  void *delegate;                                 // 0x08  VcpuStateManager::Delegate
  t_vcpu_context context;                         // 0x10  arm_guest_context_t*
  uint64_t HV_SYS_REG_ID_AA64DFR0_EL1;           // 0x18  feature_regs
  uint64_t HV_SYS_REG_ID_AA64DFR1_EL1;           // 0x20
  uint64_t HV_SYS_REG_ID_AA64ISAR0_EL1;          // 0x28
  uint64_t HV_SYS_REG_ID_AA64ISAR1_EL1;          // 0x30
  uint64_t HV_SYS_REG_ID_AA64MMFR0_EL1;          // 0x38
  uint64_t HV_SYS_REG_ID_AA64MMFR1_EL1;          // 0x40
  uint64_t HV_SYS_REG_ID_AA64MMFR2_EL1;          // 0x48
  uint64_t HV_SYS_REG_ID_AA64PFR0_EL1;           // 0x50
  uint64_t HV_SYS_REG_ID_AA64PFR1_EL1;           // 0x58
  char _pad1[0x98];                               // 0x60  remaining feature_regs
  uint64_t vcpu_config;                           // 0xF8  CfPtr<hv_vcpu_config_s>
  uint64_t vcpu_handle;                           // 0x100 hv_vcpu_t slot index (0-63)
  uint64_t vm_flags;                              // 0x108 packed: byte0=*(vm+92), byte1=(*(vm+24)!=0)
  uint64_t hcr_el2_trap_override;                 // 0x110 ORed into control_field_0 (HCR_EL2) before hv_vcpu_run
} *t_vcpus_v1520;

extern "C" t_vcpu_context _hv_vcpu_get_context(hv_vcpu_t vcpu);

extern "C" hv_return_t _hv_vcpu_get_ext_reg(hv_vcpu_t vcpu, bool error, uint64_t *value);

extern "C" hv_return_t _hv_vcpu_set_control_field(hv_vcpu_t vcpu, int index, uint64_t value);

typedef struct hypervisor_cpu {
  hv_vcpu_t vcpu;
  hv_vcpu_exit_t *vcpu_exit;
  void *cpu;
  uint8_t BRPs; // Number of breakpoints
  uint8_t WRPs; // Number of watchpoints
} *t_hypervisor_cpu;

#define HCR_EL2$DC 12

// macOS 15+: writes to trap_override field in Hv::Vcpu object;
//   Hv::Vcpu::run ORs it into control_field_0 (context+0x698) before hv_trap,
//   then clears trap_override after exit.
// Pre-15: writes directly to the canonical HCR_EL2 field in the flat _vcpus array.
inline void set_HV_SYS_REG_HCR_EL2(t_hypervisor_cpu _cpu, const uint64_t value) {
  if (@available(macOS 15.2.0, *)) {
    const auto cpu = static_cast<t_vcpus_v1520>(_cpu->cpu);
    cpu->hcr_el2_trap_override = value;
  } else if (@available(macOS 15.0.0, *)) {
    const auto cpu = static_cast<t_vcpus_v1500>(_cpu->cpu);
    cpu->hcr_el2_trap_override = value;
  } else if (@available(macOS 13.5.1, *)) {
    const auto cpu = static_cast<t_vcpus_v1351>(_cpu->cpu);
    cpu->HV_SYS_REG_HCR_EL2 = value;
  } else {
    const auto cpu = static_cast<t_vcpus>(_cpu->cpu);
    cpu->HV_SYS_REG_HCR_EL2 = value;
  }
}

static const mach_header *findHypervisorHeader(intptr_t *out_slide) {
  const mach_header *header = nullptr;
  intptr_t slide = 0;
  for (uint32_t i = 0, count = _dyld_image_count(); i < count; i++) {
    if(const char *name = _dyld_get_image_name(i); strlen(name) > 0 && strstr(name, "/System/Library/Frameworks/Hypervisor.framework/")) {
      slide = _dyld_get_image_vmaddr_slide(i);
      header = _dyld_get_image_header(i);
      break;
    }
  }
  *out_slide = slide;
  return header;
}

static void *find_vcpus() {
    static void *cached_vcpus = nullptr;
    if(cached_vcpus) {
        return cached_vcpus;
    }
    intptr_t slide = 0;
    const mach_header *header = findHypervisorHeader(&slide);
    if(header) {
        segment_command_64 *cur_seg_cmd;
        const segment_command_64 *linkedit_segment = nullptr;
        symtab_command* symtab_cmd = nullptr;
        uintptr_t cur = reinterpret_cast<uintptr_t>(header) + sizeof(struct mach_header_64);
        for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
            cur_seg_cmd = reinterpret_cast<segment_command_64 *>(cur);
            if (cur_seg_cmd->cmd == LC_SEGMENT_64) {
                if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
                    linkedit_segment = cur_seg_cmd;
                }
            } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
                symtab_cmd = reinterpret_cast<symtab_command *>(cur_seg_cmd);
            }
        }
        if(symtab_cmd && linkedit_segment) {
            const uintptr_t linkedit_base = static_cast<uintptr_t>(slide) + linkedit_segment->vmaddr - linkedit_segment->fileoff;
            auto strtab = reinterpret_cast<char *>(linkedit_base + symtab_cmd->stroff);

            auto *symtab = reinterpret_cast<struct nlist_64 *>(linkedit_base + symtab_cmd->symoff);
            for(uint i = 0; i < symtab_cmd->nsyms; i++, symtab++) {
                const uint32_t strtab_offset = symtab->n_un.n_strx;
                if(const char *symbol_name = strtab + strtab_offset; strcmp(symbol_name, "_vcpus") == 0) {
                    cached_vcpus = (void *) (symtab->n_value + slide);
                    return cached_vcpus;
                }
            }
        }
    }
    return nullptr;
}

static void *lookupVcpu(hv_vcpu_t vcpu) {
    void *vcpus = find_vcpus();
    if(!vcpus) {
        fprintf(stderr, "Find _vcpus failed: sizeof(struct vcpus)=%lu, vcpu=%llu\n", sizeof(struct vcpus), vcpu);
        abort();
        return nullptr;
    }
    void *_cpu;
    const char *os = nullptr;
    if (@available(macOS 15.0.0, *)) {
        const auto hv_vcpu = static_cast<void **>(vcpus) + vcpu;
        const auto vcpu1500 = static_cast<t_vcpus_v1500>(*hv_vcpu);
        _cpu = static_cast<void*>(&vcpu1500->context);
        os = "15.0.0";
    } else if (@available(macOS 13.5.1, *)) {
        auto _vcpus = static_cast<t_vcpus_v1351>(vcpus);
        _cpu = _vcpus + vcpu;
        os = "13.5.1";
    } else {
        auto _vcpus = static_cast<t_vcpus>(vcpus);
        _cpu = _vcpus + vcpu;
        os = "others";
    }
    if(const auto cpu = static_cast<t_vcpus>(_cpu); cpu->context == _hv_vcpu_get_context(vcpu)) {
        return cpu;
    }
    // Check _hv_vcpu_get_context in IDA
    fprintf(stderr, "Verify _vcpus failed: vcpus=%p, vcpu=%llu, os=%s\n", vcpus, vcpu, os);
    abort();
    return nullptr;
}
