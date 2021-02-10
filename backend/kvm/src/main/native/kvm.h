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
    HV_REG_PC = ARM64_CORE_REG(regs.pc),
} hv_reg_t;
