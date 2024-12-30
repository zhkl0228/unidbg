#pragma once
#include "khash.h"
#include "vcpu.h"

#define PAGE_TABLE_ADDRESS_SPACE_BITS 36
#define PAGE_BITS 14 // 16k
#define HVF_PAGE_SIZE (1ULL << PAGE_BITS)
#define HVF_PAGE_MASK (HVF_PAGE_SIZE-1)

typedef struct memory_page {
  void *addr;
  int perms;
  hv_ipa_t ipa;
} *t_memory_page;

KHASH_MAP_INIT_INT64(memory, t_memory_page)

/* Valid Syndrome Register EC field values */
enum arm_exception_class {
    EC_UNCATEGORIZED          = 0x00,
    EC_WFX_TRAP               = 0x01,
    EC_CP15RTTRAP             = 0x03,
    EC_CP15RRTTRAP            = 0x04,
    EC_CP14RTTRAP             = 0x05,
    EC_CP14DTTRAP             = 0x06,
    EC_ADVSIMDFPACCESSTRAP    = 0x07,
    EC_FPIDTRAP               = 0x08,
    EC_PACTRAP                = 0x09,
    EC_CP14RRTTRAP            = 0x0c,
    EC_BTITRAP                = 0x0d,
    EC_ILLEGALSTATE           = 0x0e,
    EC_AA32_SVC               = 0x11,
    EC_AA32_HVC               = 0x12,
    EC_AA32_SMC               = 0x13,
    EC_AA64_SVC               = 0x15,
    EC_AA64_HVC               = 0x16,
    EC_AA64_SMC               = 0x17,
    EC_SYSTEMREGISTERTRAP     = 0x18,
    EC_SVEACCESSTRAP          = 0x19,
    EC_INSNABORT              = 0x20,
    EC_INSNABORT_SAME_EL      = 0x21,
    EC_PCALIGNMENT            = 0x22,
    EC_DATAABORT              = 0x24,
    EC_DATAABORT_SAME_EL      = 0x25,
    EC_SPALIGNMENT            = 0x26,
    EC_AA32_FPTRAP            = 0x28,
    EC_AA64_FPTRAP            = 0x2c,
    EC_SERROR                 = 0x2f,
    EC_BREAKPOINT             = 0x30,
    EC_BREAKPOINT_SAME_EL     = 0x31,
    EC_SOFTWARESTEP           = 0x32,
    EC_SOFTWARESTEP_SAME_EL   = 0x33,
    EC_WATCHPOINT             = 0x34,
    EC_WATCHPOINT_SAME_EL     = 0x35,
    EC_AA32_BKPT              = 0x38,
    EC_VECTORCATCH            = 0x3a,
    EC_AA64_BKPT              = 0x3c,
};

#define ARM_EL_EC_SHIFT 26
#define ARM_EL_IL_SHIFT 25
#define ARM_EL_ISV_SHIFT 24
#define ARM_EL_IL (1 << ARM_EL_IL_SHIFT)
#define ARM_EL_ISV (1 << ARM_EL_ISV_SHIFT)

static uint32_t syn_get_ec(uint32_t syn) {
  return syn >> ARM_EL_EC_SHIFT;
}

#define PSR_MODE_EL0t	0x00000000

#define PSR_F_BIT	0x00000040
#define PSR_I_BIT	0x00000080
#define PSR_A_BIT	0x00000100
#define PSR_D_BIT	0x00000200

typedef struct cpu_context {
  vcpu_context ctx;
  uint64_t sp;
  uint64_t cpacr;
  uint64_t tpidr;
  uint64_t tpidrro;
} *t_cpu_context;
