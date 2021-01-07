#include "khash.h"
#include "com_github_unidbg_arm_backend_hypervisor_Hypervisor.h"

#include <Hypervisor/Hypervisor.h>

// Diagnostics
#define HYP_ASSERT_SUCCESS(ret) assert((hv_return_t) (ret) == HV_SUCCESS)
#define HV_REG_SP HV_SYS_REG_SP_EL0

#define PAGE_TABLE_ADDRESS_SPACE_BITS 32
#define PAGE_BITS 14 // 16k
#define PAGE_SIZE (1UL << PAGE_BITS)
#define PAGE_MASK (PAGE_SIZE-1)

typedef struct memory_page {
  void *addr;
  int perms;
  hv_ipa_t ipa;
} *t_memory_page;

KHASH_MAP_INIT_INT64(memory, t_memory_page)
