#include <linux/kvm.h>

#include "khash.h"
#include "com_github_unidbg_arm_backend_kvm_Kvm.h"

#define PAGE_TABLE_ADDRESS_SPACE_BITS 36
#define PAGE_BITS 12 // 4k
#define KVM_PAGE_SIZE (1UL << PAGE_BITS)
#define KVM_PAGE_MASK (HVF_PAGE_SIZE-1)

typedef struct memory_page {
  void *addr;
  int perms;
} *t_memory_page;

KHASH_MAP_INIT_INT64(memory, t_memory_page)

#define ARM64_CORE_REG(x)	(KVM_REG_ARM64 | KVM_REG_SIZE_U64 | \
				 KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(x))

// see https://www.kernel.org/doc/html/latest/virt/kvm/api.html
// "arm64 core/FP-SIMD registers have the following id bit patterns"
typedef enum {
    HV_REG_X0 = ARM64_CORE_REG(regs.regs[0]),
    HV_REG_X1 = ARM64_CORE_REG(regs.regs[1]),
    HV_REG_X2 = ARM64_CORE_REG(regs.regs[2]),
    HV_REG_X3 = ARM64_CORE_REG(regs.regs[3]),
    HV_REG_X4 = ARM64_CORE_REG(regs.regs[4]),
    HV_REG_X5 = ARM64_CORE_REG(regs.regs[5]),
    HV_REG_X6 = ARM64_CORE_REG(regs.regs[6]),
    HV_REG_X7 = ARM64_CORE_REG(regs.regs[7]),
    HV_REG_X8 = ARM64_CORE_REG(regs.regs[8]),
    HV_REG_X9 = ARM64_CORE_REG(regs.regs[9]),
    HV_REG_X10 = ARM64_CORE_REG(regs.regs[10]),
    HV_REG_X11 = ARM64_CORE_REG(regs.regs[11]),
    HV_REG_X12 = ARM64_CORE_REG(regs.regs[12]),
    HV_REG_X13 = ARM64_CORE_REG(regs.regs[13]),
    HV_REG_X14 = ARM64_CORE_REG(regs.regs[14]),
    HV_REG_X15 = ARM64_CORE_REG(regs.regs[15]),
    HV_REG_X16 = ARM64_CORE_REG(regs.regs[16]),
    HV_REG_X17 = ARM64_CORE_REG(regs.regs[17]),
    HV_REG_X18 = ARM64_CORE_REG(regs.regs[18]),
    HV_REG_X19 = ARM64_CORE_REG(regs.regs[19]),
    HV_REG_X20 = ARM64_CORE_REG(regs.regs[20]),
    HV_REG_X21 = ARM64_CORE_REG(regs.regs[21]),
    HV_REG_X22 = ARM64_CORE_REG(regs.regs[22]),
    HV_REG_X23 = ARM64_CORE_REG(regs.regs[23]),
    HV_REG_X24 = ARM64_CORE_REG(regs.regs[24]),
    HV_REG_X25 = ARM64_CORE_REG(regs.regs[25]),
    HV_REG_X26 = ARM64_CORE_REG(regs.regs[26]),
    HV_REG_X27 = ARM64_CORE_REG(regs.regs[27]),
    HV_REG_X28 = ARM64_CORE_REG(regs.regs[28]),
    HV_REG_X29 = ARM64_CORE_REG(regs.regs[29]),
    HV_REG_X30 = ARM64_CORE_REG(regs.regs[30]),
    HV_REG_FPCR = ARM64_CORE_REG(fp_regs.fpcr),
    HV_REG_FPSR = ARM64_CORE_REG(fp_regs.fpsr),
    HV_REG_PC = ARM64_CORE_REG(regs.pc),
    HV_REG_LR = HV_REG_X30,
    HV_REG_CPSR = ARM64_CORE_REG(regs.pstate),
} hv_reg_t;

// see https://github.com/torvalds/linux/blob/master/tools/testing/selftests/kvm/aarch64/get-reg-list.c
typedef enum {
    HV_SYS_REG_SP_EL0 = ARM64_CORE_REG(regs.sp),
    HV_SYS_REG_SP_EL1 = ARM64_CORE_REG(sp_el1),
    HV_SYS_REG_ELR_EL1 = ARM64_CORE_REG(elr_el1),
    HV_SYS_REG_SPSR_EL1 = ARM64_CORE_REG(spsr[0]),
    HV_SYS_REG_SCTLR_EL1 = ARM64_SYS_REG(3, 0, 1, 0, 0),
    HV_SYS_REG_ESR_EL1 = ARM64_SYS_REG(3, 0, 5, 2, 0),
    HV_SYS_REG_FAR_EL1 = ARM64_SYS_REG(3, 0, 6, 0, 0),
    HV_SYS_REG_VBAR_EL1 = ARM64_SYS_REG(3, 0, 12, 0, 0),
    HV_SYS_REG_CNTV_CVAL_EL0 = ARM64_SYS_REG(3, 3, 14, 3, 2),
    HV_SYS_REG_CNTV_CTL_EL0 = ARM64_SYS_REG(3, 3, 14, 3, 1),
    HV_SYS_REG_CNTKCTL_EL1 = ARM64_SYS_REG(3, 0, 14, 1, 0),
    HV_SYS_REG_MIDR_EL1 = ARM64_SYS_REG(3, 0, 0, 0, 0),
    HV_SYS_REG_ID_AA64MMFR0_EL1 = ARM64_SYS_REG(3, 0, 0, 7, 0),
    HV_SYS_REG_ID_AA64MMFR2_EL1 = ARM64_SYS_REG(3, 0, 0, 7, 2),
    HV_SYS_REG_TPIDR_EL0 = ARM64_SYS_REG(3, 3, 13, 0, 2),
    HV_SYS_REG_CPACR_EL1 = ARM64_SYS_REG(3, 0, 1, 0, 2),
    HV_SYS_REG_TPIDRRO_EL0 = ARM64_SYS_REG(3, 3, 13, 0, 3),
} hv_sys_reg_t;
