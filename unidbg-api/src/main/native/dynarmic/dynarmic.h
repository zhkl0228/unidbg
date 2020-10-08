#include "khash.h"
#include "com_github_unidbg_arm_backend_dynarmic_Dynarmic.h"

#define PAGE_SIZE 0x1000 // 4k

typedef struct memory_page {
  char *ptr;
  int perms;
} *t_memory_page;

KHASH_MAP_INIT_INT64(memory, t_memory_page)

typedef struct dynarmic {
  bool is64Bit;
  khash_t(memory) *memory;
} *t_dynarmic;
