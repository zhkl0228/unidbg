#include <vector>

#ifdef DYNARMIC_MASTER
#include <dynarmic/interface/A32/a32.h>
#include <dynarmic/interface/A32/config.h>

#include <dynarmic/interface/A64/a64.h>
#include <dynarmic/interface/A64/config.h>

#include <dynarmic/interface/exclusive_monitor.h>
#else
#include <dynarmic/A32/a32.h>
#include <dynarmic/A32/config.h>

#include <dynarmic/A64/a64.h>
#include <dynarmic/A64/config.h>

#include <dynarmic/exclusive_monitor.h>
#endif


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

using Vector = std::array<std::uint64_t, 2>;
typedef struct context64 {
  std::uint64_t sp;
  std::uint64_t pc;
  std::array<std::uint64_t, 31> registers;
  std::array<Vector, 32> vectors;
  std::uint32_t fpcr;
  std::uint32_t fpsr;
  std::uint32_t pstate;
  std::uint64_t tpidr_el0;
  std::uint64_t tpidrro_el0;
} *t_context64;

typedef struct context32 {
  std::array<std::uint32_t, 16> regs;
  std::array<std::uint32_t, 64> extRegs;
  std::uint32_t cpsr;
  std::uint32_t fpscr;
  std::uint32_t uro;
} *t_context32;
