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
