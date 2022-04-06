#include "com_github_unidbg_arm_backend_unicorn_Unicorn.h"
#include "khash.h"
#include <unicorn/unicorn.h>

#define SEARCH_BPS_COUNT 8

KHASH_MAP_INIT_INT64(64, char)

typedef struct unicorn {
  khash_t(64) *bps_map;
  uint64_t bps[SEARCH_BPS_COUNT];
  uc_engine *uc;
  jint singleStep;
  jboolean fastDebug;
  uc_hook count_hook;
  uint64_t emu_count;
  uint64_t emu_counter;
} *t_unicorn;

struct new_hook {
    uc_hook hh;
    jobject hook;
    t_unicorn unicorn;
};

void armeb_uc_init() {
  fprintf(stderr, "Unsupported armeb\n");
  abort();
}
void arm64eb_uc_init() {
  fprintf(stderr, "Unsupported arm64eb\n");
  abort();
}
void arm64eb_context_reg_read() {
  fprintf(stderr, "Unsupported arm64eb\n");
  abort();
}
void arm64eb_context_reg_write() {
  fprintf(stderr, "Unsupported arm64eb\n");
  abort();
}
void ARM64_REGS_STORAGE_SIZE_aarch64eb() {
  fprintf(stderr, "Unsupported aarch64eb\n");
  abort();
}
