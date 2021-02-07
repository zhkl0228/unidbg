#include <dynarmic/A32/a32.h>
#include <dynarmic/A32/config.h>

#include <dynarmic/A64/a64.h>
#include <dynarmic/A64/config.h>

#include <dynarmic/exclusive_monitor.h>

#include "khash.h"
#include "com_github_unidbg_arm_backend_dynarmic_Dynarmic.h"

#define PAGE_TABLE_ADDRESS_SPACE_BITS 36
#define DYN_PAGE_BITS 12 // 4k
#define DYN_PAGE_SIZE (1ULL << DYN_PAGE_BITS)
#define DYN_PAGE_MASK (DYN_PAGE_SIZE-1)
#define UC_PROT_WRITE 2

typedef struct memory_page {
  void *addr;
  int perms;
} *t_memory_page;

KHASH_MAP_INIT_INT64(memory, t_memory_page)
