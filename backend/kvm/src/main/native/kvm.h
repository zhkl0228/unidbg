#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <linux/kvm.h>

#include "khash.h"
#include "com_github_unidbg_arm_backend_kvm_Kvm.h"

#define REG_VBAR_EL1 0xf0000000LL
#define MMIO_TRAP_ADDRESS 0x76543210LL

#define PAGE_TABLE_ADDRESS_SPACE_BITS 36
#define PAGE_BITS 12 // 4k
#define KVM_PAGE_SIZE (1UL << PAGE_BITS)
#define KVM_PAGE_MASK (KVM_PAGE_SIZE-1)

typedef struct memory_page {
  void *addr;
  int perms;
} *t_memory_page;

KHASH_MAP_INIT_INT64(memory, t_memory_page)

#define ARM64_CORE_REG(x)	(KVM_REG_ARM64 | KVM_REG_SIZE_U64 | \
				 KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(x))

#define ARM64_FP_REG(x)	    (KVM_REG_ARM64 | KVM_REG_SIZE_U128 | \
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
    HV_REG_FPCR = KVM_REG_ARM64 | KVM_REG_SIZE_U32 | KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(fp_regs.fpcr),
    HV_REG_FPSR = KVM_REG_ARM64 | KVM_REG_SIZE_U32 | KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(fp_regs.fpsr),
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
    HV_SYS_REG_MIDR_EL1 = ARM64_SYS_REG(3, 0, 0, 0, 0),
    HV_SYS_REG_ID_AA64MMFR0_EL1 = ARM64_SYS_REG(3, 0, 0, 7, 0),
    HV_SYS_REG_ID_AA64MMFR2_EL1 = ARM64_SYS_REG(3, 0, 0, 7, 2),
    HV_SYS_REG_SCTLR_EL1 = ARM64_SYS_REG(3, 0, 1, 0, 0),
    HV_SYS_REG_CPACR_EL1 = ARM64_SYS_REG(3, 0, 1, 0, 2),
    HV_SYS_REG_ESR_EL1 = ARM64_SYS_REG(3, 0, 5, 2, 0),
    HV_SYS_REG_FAR_EL1 = ARM64_SYS_REG(3, 0, 6, 0, 0),
    HV_SYS_REG_VBAR_EL1 = ARM64_SYS_REG(3, 0, 12, 0, 0),
    HV_SYS_REG_CNTKCTL_EL1 = ARM64_SYS_REG(3, 0, 14, 1, 0),
    HV_SYS_REG_TPIDR_EL0 = ARM64_SYS_REG(3, 3, 13, 0, 2),
    HV_SYS_REG_TPIDRRO_EL0 = ARM64_SYS_REG(3, 3, 13, 0, 3),
    HV_SYS_REG_CNTV_CTL_EL0 = ARM64_SYS_REG(3, 3, 14, 3, 1),
    HV_SYS_REG_CNTV_CVAL_EL0 = ARM64_SYS_REG(3, 3, 14, 3, 2),
    HV_SYS_REG_FPEXC32_EL2 = ARM64_SYS_REG(3, 4, 5, 3, 0),
} hv_sys_reg_t;

typedef enum {
    HV_SIMD_FP_REG_Q0 = ARM64_FP_REG(fp_regs.vregs[0]),
    HV_SIMD_FP_REG_Q1 = ARM64_FP_REG(fp_regs.vregs[1]),
    HV_SIMD_FP_REG_Q2 = ARM64_FP_REG(fp_regs.vregs[2]),
    HV_SIMD_FP_REG_Q3 = ARM64_FP_REG(fp_regs.vregs[3]),
    HV_SIMD_FP_REG_Q4 = ARM64_FP_REG(fp_regs.vregs[4]),
    HV_SIMD_FP_REG_Q5 = ARM64_FP_REG(fp_regs.vregs[5]),
    HV_SIMD_FP_REG_Q6 = ARM64_FP_REG(fp_regs.vregs[6]),
    HV_SIMD_FP_REG_Q7 = ARM64_FP_REG(fp_regs.vregs[7]),
    HV_SIMD_FP_REG_Q8 = ARM64_FP_REG(fp_regs.vregs[8]),
    HV_SIMD_FP_REG_Q9 = ARM64_FP_REG(fp_regs.vregs[9]),
    HV_SIMD_FP_REG_Q10 = ARM64_FP_REG(fp_regs.vregs[10]),
    HV_SIMD_FP_REG_Q11 = ARM64_FP_REG(fp_regs.vregs[11]),
    HV_SIMD_FP_REG_Q12 = ARM64_FP_REG(fp_regs.vregs[12]),
    HV_SIMD_FP_REG_Q13 = ARM64_FP_REG(fp_regs.vregs[13]),
    HV_SIMD_FP_REG_Q14 = ARM64_FP_REG(fp_regs.vregs[14]),
    HV_SIMD_FP_REG_Q15 = ARM64_FP_REG(fp_regs.vregs[15]),
    HV_SIMD_FP_REG_Q16 = ARM64_FP_REG(fp_regs.vregs[16]),
    HV_SIMD_FP_REG_Q17 = ARM64_FP_REG(fp_regs.vregs[17]),
    HV_SIMD_FP_REG_Q18 = ARM64_FP_REG(fp_regs.vregs[18]),
    HV_SIMD_FP_REG_Q19 = ARM64_FP_REG(fp_regs.vregs[19]),
    HV_SIMD_FP_REG_Q20 = ARM64_FP_REG(fp_regs.vregs[20]),
    HV_SIMD_FP_REG_Q21 = ARM64_FP_REG(fp_regs.vregs[21]),
    HV_SIMD_FP_REG_Q22 = ARM64_FP_REG(fp_regs.vregs[22]),
    HV_SIMD_FP_REG_Q23 = ARM64_FP_REG(fp_regs.vregs[23]),
    HV_SIMD_FP_REG_Q24 = ARM64_FP_REG(fp_regs.vregs[24]),
    HV_SIMD_FP_REG_Q25 = ARM64_FP_REG(fp_regs.vregs[25]),
    HV_SIMD_FP_REG_Q26 = ARM64_FP_REG(fp_regs.vregs[26]),
    HV_SIMD_FP_REG_Q27 = ARM64_FP_REG(fp_regs.vregs[27]),
    HV_SIMD_FP_REG_Q28 = ARM64_FP_REG(fp_regs.vregs[28]),
    HV_SIMD_FP_REG_Q29 = ARM64_FP_REG(fp_regs.vregs[29]),
    HV_SIMD_FP_REG_Q30 = ARM64_FP_REG(fp_regs.vregs[30]),
    HV_SIMD_FP_REG_Q31 = ARM64_FP_REG(fp_regs.vregs[31]),
} hv_simd_fp_reg_t;

#define HV_SUCCESS 0
typedef int hv_return_t;
typedef struct kvm_cpu *hv_vcpu_t;

typedef __uint128_t hv_simd_fp_uchar16_t;

#define HYP_ASSERT_SUCCESS(ret) assert((hv_return_t) (ret) == HV_SUCCESS)

hv_return_t hv_vcpu_get_reg(hv_vcpu_t vcpu, hv_reg_t reg, uint64_t *value);
hv_return_t hv_vcpu_set_reg(hv_vcpu_t vcpu, hv_reg_t reg, uint64_t value);
hv_return_t hv_vcpu_get_sys_reg(hv_vcpu_t vcpu, hv_sys_reg_t reg, uint64_t *value);
hv_return_t hv_vcpu_set_sys_reg(hv_vcpu_t vcpu, hv_sys_reg_t reg, uint64_t value);
hv_return_t hv_vcpu_get_simd_fp_reg(hv_vcpu_t vcpu, hv_simd_fp_reg_t reg, hv_simd_fp_uchar16_t *value);
hv_return_t hv_vcpu_set_simd_fp_reg(hv_vcpu_t vcpu, hv_simd_fp_reg_t reg, hv_simd_fp_uchar16_t value);

/* SPSR_ELx bits for exceptions taken from AArch32 */
#define PSR_AA32_MODE_USR       0x00000010
#define PSR_AA32_T_BIT          0x00000020
#define PSR_AA32_F_BIT          0x00000040
#define PSR_AA32_I_BIT          0x00000080
#define PSR_AA32_A_BIT          0x00000100
#define PSR_AA32_E_BIT          0x00000200
