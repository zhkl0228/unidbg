#include "com_github_unidbg_arm_backend_unicorn_Unicorn.h"
#include "khash.h"
#include <unicorn/unicorn.h>

#define SEARCH_BPS_COUNT 8

KHASH_MAP_INIT_INT64(64, char)

struct new_hook {
    uc_hook hh;
    jobject hook;
};

typedef struct unicorn {
  khash_t(64) *bps_map;
  uc_engine *uc;
} *t_unicorn;
