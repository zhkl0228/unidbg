#include "khash.h"
#include "com_github_unidbg_arm_backend_hypervisor_Hypervisor.h"

// Diagnostics
#define HYP_ASSERT_SUCCESS(ret) assert((hv_return_t) (ret) == HV_SUCCESS)

#define PAGE_TABLE_ADDRESS_SPACE_BITS 32
#define PAGE_BITS 12 // 4k

typedef struct memory_page {
  void *addr;
  int perms;
} *t_memory_page;

KHASH_MAP_INIT_INT64(memory, t_memory_page)
