#include <unistd.h>
#include <cassert>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/errno.h>

#include "hypervisor.h"
#include "com_github_unidbg_arm_backend_hypervisor_Hypervisor.h"

typedef struct hypervisor {
  bool is64Bit = false;
  khash_t(memory) *memory = nullptr;
  size_t num_page_table_entries = 0;
  void **page_table = nullptr;
  pthread_key_t cpu_key = 0;
  jobject callback = nullptr;
  bool stop_request = false;
  uint64_t sp = 0ULL;
  uint64_t cpacr = 0ULL;
  uint64_t tpidr = 0ULL;
  uint64_t tpidrro = 0ULL;
} *t_hypervisor;

static jmethodID handleException = nullptr;
static jmethodID handleUnknownException = nullptr;

static char *get_memory_page(khash_t(memory) *memory, uint64_t vaddr, size_t num_page_table_entries, void **page_table) {
    uint64_t idx = vaddr >> PAGE_BITS;
    if(page_table && idx < num_page_table_entries) {
      return (char *)page_table[idx];
    }
    uint64_t base = vaddr & ~HVF_PAGE_MASK;
    khiter_t k = kh_get(memory, memory, base);
    if(k == kh_end(memory)) {
      return nullptr;
    }
    t_memory_page page = kh_value(memory, k);
    return (char *)page->addr;
}

static inline void *get_memory(khash_t(memory) *memory, uint64_t vaddr, size_t num_page_table_entries, void **page_table) {
    char *page = get_memory_page(memory, vaddr, num_page_table_entries, page_table);
    return page ? &page[vaddr & HVF_PAGE_MASK] : nullptr;
}

static t_vcpu_context get_vcpu_context(t_hypervisor_cpu cpu) {
  auto vcpus = (t_vcpus) cpu->cpu;
  return vcpus->context;
}

static bool handle_exception(JNIEnv *env, t_hypervisor hypervisor, t_hypervisor_cpu cpu) {
  uint64_t syndrome = cpu->vcpu_exit->exception.syndrome;
  uint32_t ec = syn_get_ec(syndrome);
  switch(ec) {
    case EC_AA64_HVC: { // Exception Class 0x16 is "HVC instruction execution in AArch64 state, when HVC is not disabled."
      uint64_t esr = 0;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_ESR_EL1, &esr));
      uint64_t far = 0;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_FAR_EL1, &far));
      uint64_t elr;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_ELR_EL1, &elr));
      uint64_t cpsr = 0;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_SPSR_EL1, &cpsr));
      jboolean handled = env->CallBooleanMethod(hypervisor->callback, handleException, esr, far, elr, cpsr);
      if (env->ExceptionCheck()) {
        return false;
      }
      return handled == JNI_TRUE;
    }
    case EC_AA64_SVC:
    default:
      uint64_t pc = 0;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(cpu->vcpu, HV_REG_PC, &pc));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_ELR_EL1, pc));
      uint64_t cpsr = 0;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_SPSR_EL1, &cpsr));
      uint64_t sp = 0;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_SP_EL0, &sp));
      uint64_t esr = 0;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_ESR_EL1, &esr));
      uint64_t far = 0;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_FAR_EL1, &far));
      env->CallVoidMethod(hypervisor->callback, handleUnknownException, ec, esr, far, cpu->vcpu_exit->exception.virtual_address);
      fprintf(stderr, "Unexpected VM exception: 0x%llx, EC 0x%x, VirtAddr 0x%llx, IPA 0x%llx, PC 0x%llx, SPSR_EL1 0x%llx, SP_EL0 0x%llx, ESR_EL1 0x%llx, FAR_EL1 0x%llx\n",
                          syndrome,
                          ec,
                          cpu->vcpu_exit->exception.virtual_address,
                          cpu->vcpu_exit->exception.physical_address,
                          pc,
                          cpsr,
                          sp,
                          esr,
                          far
                      );
      return false;
  }
  return true;
}

static int cpu_loop(JNIEnv *env, t_hypervisor hypervisor, t_hypervisor_cpu cpu) {
  hypervisor->stop_request = false;
  HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_TPIDR_EL0, hypervisor->tpidr));
  HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_CPACR_EL1, hypervisor->cpacr));
  while(true) {
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_TPIDRRO_EL0, hypervisor->tpidrro));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_REG_SP, hypervisor->sp));
    HYP_ASSERT_SUCCESS(hv_vcpu_run(cpu->vcpu));
    HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_REG_SP, &hypervisor->sp));
    HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_TPIDRRO_EL0, &hypervisor->tpidrro));

    switch(cpu->vcpu_exit->reason) {
      case HV_EXIT_REASON_EXCEPTION: {
        if(handle_exception(env, hypervisor, cpu)) {
          break;
        } else {
          return 1;
        }
      }
      default:
        fprintf(stderr, "Unexpected VM exit reason: %d\n", cpu->vcpu_exit->reason);
        abort();
        break;
    }

    if(hypervisor->stop_request) {
      break;
    }
  }
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    testVcpu
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_testVcpu
  (JNIEnv *env, jclass clazz) {
  auto cpu = (t_hypervisor_cpu) calloc(1, sizeof(struct hypervisor_cpu));
  HYP_ASSERT_SUCCESS(hv_vcpu_create(&cpu->vcpu, &cpu->vcpu_exit, nullptr));
  void *vcpu = lookupVcpu(cpu->vcpu);
  printf("do test cpu=%llu, vcpu=%p\n", cpu->vcpu, vcpu);
}

static t_hypervisor_cpu get_hypervisor_cpu(JNIEnv *env, t_hypervisor hypervisor) {
  auto cpu = (t_hypervisor_cpu) pthread_getspecific(hypervisor->cpu_key);
  if(cpu) {
    return cpu;
  } else {
    cpu = (t_hypervisor_cpu) calloc(1, sizeof(struct hypervisor_cpu));
    HYP_ASSERT_SUCCESS(hv_vcpu_create(&cpu->vcpu, &cpu->vcpu_exit, nullptr));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_VBAR_EL1, com_github_unidbg_arm_backend_hypervisor_Hypervisor_REG_VBAR_EL1));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_SCTLR_EL1, 0x4c5d864));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_CNTV_CVAL_EL0, 0x0));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_CNTV_CTL_EL0, 0x0));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_CNTKCTL_EL1, 0x0));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_MIDR_EL1, 0x410fd083));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_ID_AA64MMFR0_EL1, 0x5));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_ID_AA64MMFR2_EL1, 0x10000));

    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_MDSCR_EL1, 1 << 15)); // MDSCR_EL1.MDE
    uint64_t id_aa64dfr0 = 0;
    HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_ID_AA64DFR0_EL1, &id_aa64dfr0));
    uint8_t BRPs = (id_aa64dfr0 >> 12) & 0xf;
    uint8_t WRPs = (id_aa64dfr0 >> 20) & 0xf;
    cpu->BRPs = BRPs + 1;
    cpu->WRPs = WRPs + 1;

    // Trap debug access (BRK)
    HYP_ASSERT_SUCCESS(hv_vcpu_set_trap_debug_exceptions(cpu->vcpu, false));
    assert(pthread_setspecific(hypervisor->cpu_key, cpu) == 0);

    void *vcpu = lookupVcpu(cpu->vcpu);
    assert(vcpu != nullptr);
    cpu->cpu = vcpu;

    if(hypervisor->is64Bit) {
      uint64_t value = 1LL << HCR_EL2$DC; // set stage 1 as normal memory
      set_HV_SYS_REG_HCR_EL2(cpu, value);
    } else {
      abort();
    }

    return cpu;
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    getCpuContext
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_getCpuContext
        (JNIEnv *env, jclass clazz, jlong handle) {
    auto hypervisor = (t_hypervisor) handle;
    t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
    return (jlong) _hv_vcpu_get_context(cpu->vcpu);
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    lookupVcpu
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_lookupVcpu
    (JNIEnv *env, jclass clazz, jlong handle) {
    auto hypervisor = (t_hypervisor) handle;
    t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
    return (jlong) cpu->cpu;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    getVCpus
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_getVCpus
        (JNIEnv *env, jclass clazz) {
    return (jlong) find_vcpus();
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    getBRPs
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_getBRPs
  (JNIEnv *env, jclass clazz, jlong handle) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  return cpu->BRPs;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    getWRPs
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_getWRPs
  (JNIEnv *env, jclass clazz, jlong handle) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  return cpu->WRPs;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    enable_single_step
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_enable_1single_1step
  (JNIEnv *env, jclass clazz, jlong handle, jboolean status) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  uint64_t mdscr_el1 = 0;
  uint64_t cpsr = 0;
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_MDSCR_EL1, &mdscr_el1));
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_SPSR_EL1, &cpsr));

  if(status) {
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_MDSCR_EL1, mdscr_el1 | 0x1ULL)); // MDSCR_EL1.SS
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_SPSR_EL1, cpsr | com_github_unidbg_arm_backend_hypervisor_Hypervisor_PSTATE_00024SS));
  } else {
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_MDSCR_EL1, mdscr_el1 & ~0x1ULL)); // MDSCR_EL1.SS
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_SPSR_EL1, cpsr & ~com_github_unidbg_arm_backend_hypervisor_Hypervisor_PSTATE_00024SS));
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    install_watchpoint
 * Signature: (JIJJ)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_install_1watchpoint
  (JNIEnv *env, jclass clazz, jlong handle, jint n, jlong dbgwcr, jlong dbgwvr) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  if(n < 0 || n >= cpu->WRPs) {
    abort();
    return;
  }
  switch (n) {
    case 0:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR0_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR0_EL1, dbgwvr));
      break;
    case 1:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR1_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR1_EL1, dbgwvr));
      break;
    case 2:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR2_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR2_EL1, dbgwvr));
      break;
    case 3:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR3_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR3_EL1, dbgwvr));
      break;
    case 4:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR4_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR4_EL1, dbgwvr));
      break;
    case 5:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR5_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR5_EL1, dbgwvr));
      break;
    case 6:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR6_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR6_EL1, dbgwvr));
      break;
    case 7:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR7_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR7_EL1, dbgwvr));
      break;
    case 8:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR8_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR8_EL1, dbgwvr));
      break;
    case 9:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR9_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR9_EL1, dbgwvr));
      break;
    case 10:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR10_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR10_EL1, dbgwvr));
      break;
    case 11:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR11_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR11_EL1, dbgwvr));
      break;
    case 12:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR12_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR12_EL1, dbgwvr));
      break;
    case 13:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR13_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR13_EL1, dbgwvr));
      break;
    case 14:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR14_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR14_EL1, dbgwvr));
      break;
    case 15:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWCR15_EL1, dbgwcr));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGWVR15_EL1, dbgwvr));
      break;
    default:
      abort();
      break;
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    install_hw_breakpoint
 * Signature: (JIJ)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_install_1hw_1breakpoint
  (JNIEnv *env, jclass clazz, jlong handle, jint n, jlong address) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  if(n < 0 || n >= cpu->BRPs) {
    abort();
    return;
  }
  switch (n) {
    case 0:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR0_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR0_EL1, address));
      break;
    case 1:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR1_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR1_EL1, address));
      break;
    case 2:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR2_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR2_EL1, address));
      break;
    case 3:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR3_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR3_EL1, address));
      break;
    case 4:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR4_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR4_EL1, address));
      break;
    case 5:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR5_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR5_EL1, address));
      break;
    case 6:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR6_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR6_EL1, address));
      break;
    case 7:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR7_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR7_EL1, address));
      break;
    case 8:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR8_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR8_EL1, address));
      break;
    case 9:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR9_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR9_EL1, address));
      break;
    case 10:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR10_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR10_EL1, address));
      break;
    case 11:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR11_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR11_EL1, address));
      break;
    case 12:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR12_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR12_EL1, address));
      break;
    case 13:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR13_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR13_EL1, address));
      break;
    case 14:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR14_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR14_EL1, address));
      break;
    case 15:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR15_EL1, 0x5));
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBVR15_EL1, address));
      break;
    default:
      abort();
      break;
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    disable_hw_breakpoint
 * Signature: (JI)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_disable_1hw_1breakpoint
  (JNIEnv *env, jclass clazz, jlong handle, jint n) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  if(n < 0 || n >= cpu->BRPs) {
    abort();
    return;
  }
  switch (n) {
    case 0:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR0_EL1, 0x0));
      break;
    case 1:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR1_EL1, 0x0));
      break;
    case 2:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR2_EL1, 0x0));
      break;
    case 3:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR3_EL1, 0x0));
      break;
    case 4:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR4_EL1, 0x0));
      break;
    case 5:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR5_EL1, 0x0));
      break;
    case 6:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR6_EL1, 0x0));
      break;
    case 7:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR7_EL1, 0x0));
      break;
    case 8:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR8_EL1, 0x0));
      break;
    case 9:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR9_EL1, 0x0));
      break;
    case 10:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR10_EL1, 0x0));
      break;
    case 11:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR11_EL1, 0x0));
      break;
    case 12:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR12_EL1, 0x0));
      break;
    case 13:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR13_EL1, 0x0));
      break;
    case 14:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR14_EL1, 0x0));
      break;
    case 15:
      HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_DBGBCR15_EL1, 0x0));
      break;
    default:
      abort();
      break;
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    getPageSize
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_getPageSize
  (JNIEnv *env, jclass clazz) {
  long sz = sysconf(_SC_PAGESIZE);
  return (jint) sz;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    emu_start
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_emu_1start
  (JNIEnv *env, jclass clazz, jlong handle, jlong pc) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);

  if(hypervisor->is64Bit) {
    uint32_t cpsr = PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL0t;
    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(cpu->vcpu, HV_REG_CPSR, cpsr));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(cpu->vcpu, HV_REG_PC, pc));
  } else {
    abort();
  }
  return cpu_loop(env, hypervisor, cpu);
}

static void destroy_hypervisor_cpu(void *data) {
//  printf("destroy_hypervisor_cpu data=%p\n", data);
  auto cpu = (t_hypervisor_cpu) data;
  HYP_ASSERT_SUCCESS(hv_vcpu_destroy(cpu->vcpu));
  free(cpu);
}

__attribute__((constructor))
static void init() {
  uint32_t max_vcpu_count = 0;
  hv_vm_get_max_vcpu_count(&max_vcpu_count);
  hv_vm_config_t config = nullptr;
  if (@available(macOS 13.0.0, *)) {
    config = hv_vm_config_create();
  }
#if __MAC_15_0
  if (@available(macOS 15.0.0, *)) {
    HYP_ASSERT_SUCCESS(hv_vm_config_set_el2_enabled(config, false));
  }
#endif
  hv_return_t ret = hv_vm_create(config);
  if(config) {
      os_release(config);
  }
  if(HV_SUCCESS != ret) {
    fprintf(stderr, "Follow instructions: https://github.com/zhkl0228/unidbg/blob/master/backend/hypervisor/README.md\nNumber of vCPUs that the hypervisor supports: %u\n", max_vcpu_count);
  }
  HYP_ASSERT_SUCCESS(ret);
}

__attribute__((destructor))
static void destroy() {
  hv_vm_destroy();
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    setHypervisorCallback
 * Signature: (JLcom/github/unidbg/arm/backend/hypervisor/HypervisorCallback;)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_setHypervisorCallback
  (JNIEnv *env, jclass clazz, jlong handle, jobject callback) {
  auto hypervisor = (t_hypervisor) handle;
  hypervisor->callback = env->NewGlobalRef(callback);
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    nativeInitialize
 * Signature: (Z)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_nativeInitialize
  (JNIEnv *env, jclass clazz, jboolean is64Bit) {
  auto hypervisor = (t_hypervisor) calloc(1, sizeof(struct hypervisor));
  if(hypervisor == nullptr) {
    fprintf(stderr, "calloc hypervisor failed: size=%lu\n", sizeof(struct hypervisor));
    abort();
    return 0;
  }
  hypervisor->is64Bit = is64Bit == JNI_TRUE;
  hypervisor->memory = kh_init(memory);
  if(hypervisor->memory == nullptr) {
    fprintf(stderr, "kh_init memory failed\n");
    abort();
    return 0;
  }
  int ret = kh_resize(memory, hypervisor->memory, 0x1000);
  if(ret == -1) {
    fprintf(stderr, "kh_resize memory failed\n");
    abort();
    return 0;
  }
  hypervisor->num_page_table_entries = 1ULL << (PAGE_TABLE_ADDRESS_SPACE_BITS - PAGE_BITS);
  size_t size = hypervisor->num_page_table_entries * sizeof(void*);
  hypervisor->page_table = (void **)mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if(hypervisor->page_table == MAP_FAILED) {
    fprintf(stderr, "createVM mmap failed[%s->%s:%d] size=0x%zx, errno=%d, msg=%s\n", __FILE__, __func__, __LINE__, size, errno, strerror(errno));
    abort();
    return 0;
  }
  assert(pthread_key_create(&hypervisor->cpu_key, destroy_hypervisor_cpu) == 0);
  return (jlong) hypervisor;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    nativeDestroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_nativeDestroy
  (JNIEnv *env, jclass clazz, jlong handle) {
  auto hypervisor = (t_hypervisor) handle;
  khash_t(memory) *memory = hypervisor->memory;
  for (auto k = kh_begin(memory); k < kh_end(memory); k++) {
    if(kh_exist(memory, k)) {
      t_memory_page page = kh_value(memory, k);
      HYP_ASSERT_SUCCESS(hv_vm_unmap(page->ipa, HVF_PAGE_SIZE));
      int ret = munmap(page->addr, HVF_PAGE_SIZE);
      if(ret != 0) {
        fprintf(stderr, "munmap failed[%s->%s:%d]: addr=%p, ret=%d\n", __FILE__, __func__, __LINE__, page->addr, ret);
      }
      free(page);
    }
  }
  kh_destroy(memory, memory);
  if(hypervisor->callback) {
    env->DeleteGlobalRef(hypervisor->callback);
  }
  if(hypervisor->page_table) {
    int ret = munmap(hypervisor->page_table, hypervisor->num_page_table_entries * sizeof(void*));
    if(ret != 0) {
      fprintf(stderr, "munmap failed[%s->%s:%d]: page_table=%p, ret=%d\n", __FILE__, __func__, __LINE__, hypervisor->page_table, ret);
    }
  }
  free(hypervisor);
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    mem_unmap
 * Signature: (JJJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_mem_1unmap
  (JNIEnv *env, jclass clazz, jlong handle, jlong address, jlong size) {
  if(address & HVF_PAGE_MASK) {
    return 1;
  }
  if(size == 0 || (size & HVF_PAGE_MASK)) {
    return 2;
  }

  HYP_ASSERT_SUCCESS(hv_vm_unmap(address, size));

  auto hypervisor = (t_hypervisor) handle;
  khash_t(memory) *memory = hypervisor->memory;
  for(uint64_t vaddr = address; vaddr < address + size; vaddr += HVF_PAGE_SIZE) {
    uint64_t idx = vaddr >> PAGE_BITS;
    khiter_t k = kh_get(memory, memory, vaddr);
    if(k == kh_end(memory)) {
      fprintf(stderr, "mem_unmap failed[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
      return 3;
    }
    if(hypervisor->page_table && idx < hypervisor->num_page_table_entries) {
      hypervisor->page_table[idx] = nullptr;
    }
    t_memory_page page = kh_value(memory, k);
    int ret = munmap(page->addr, HVF_PAGE_SIZE);
    if(ret != 0) {
      fprintf(stderr, "munmap failed[%s->%s:%d]: addr=%p, ret=%d\n", __FILE__, __func__, __LINE__, page->addr, ret);
    }
    free(page);
    kh_del(memory, memory, k);
  }
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    mem_map
 * Signature: (JJJI)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_mem_1map
  (JNIEnv *env, jclass clazz, jlong handle, jlong address, jlong size, jint perms) {
  if(address & HVF_PAGE_MASK) {
    return 1;
  }
  if(size == 0 || (size & HVF_PAGE_MASK)) {
    return 2;
  }
  auto hypervisor = (t_hypervisor) handle;
  khash_t(memory) *memory = hypervisor->memory;

  char *start_addr = (char *) mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if(start_addr == MAP_FAILED) {
    fprintf(stderr, "mmap failed[%s->%s:%d]: start_addr=%p\n", __FILE__, __func__, __LINE__, start_addr);
    return 4;
  }

  if(hv_vm_map(start_addr, address, size, perms) != HV_SUCCESS) {
    fprintf(stderr, "hv_vm_map failed start_addr=%p, ipa=0x%lx, perms=0x%x\n", start_addr, address, perms);
    return 6;
  }

  int ret;
  for(uint64_t vaddr = address; vaddr < address + size; vaddr += HVF_PAGE_SIZE) {
    uint64_t idx = vaddr >> PAGE_BITS;
    if(kh_get(memory, memory, vaddr) != kh_end(memory)) {
      fprintf(stderr, "mem_map failed[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
      return 3;
    }

    void *addr = &start_addr[vaddr - address];
    if(hypervisor->page_table && idx < hypervisor->num_page_table_entries) {
      hypervisor->page_table[idx] = addr;
    } else {
      fprintf(stderr, "mem_map warning[%s->%s:%d]: addr=%p, page_table=%p, idx=%llu, num_page_table_entries=%zu\n", __FILE__, __func__, __LINE__, (void*)addr, hypervisor->page_table, idx, hypervisor->num_page_table_entries);
    }
    khiter_t k = kh_put(memory, memory, vaddr, &ret);
    auto page = (t_memory_page) calloc(1, sizeof(struct memory_page));
    if(page == nullptr) {
      fprintf(stderr, "calloc page failed: size=%lu\n", sizeof(struct memory_page));
      abort();
      return 0;
    }
    page->addr = addr;
    page->perms = perms;
    page->ipa = vaddr;
    kh_value(memory, k) = page;
  }
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    mem_protect
 * Signature: (JJJI)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_mem_1protect
  (JNIEnv *env, jclass clazz, jlong handle, jlong address, jlong size, jint perms) {
  if(address & HVF_PAGE_MASK) {
    return 1;
  }
  if(size == 0 || (size & HVF_PAGE_MASK)) {
    return 2;
  }
  if(hv_vm_protect(address, size, perms) != HV_SUCCESS) {
    fprintf(stderr, "hv_vm_protect failed address=%p, size=0x%lx, perms=0x%x\n", (void*) address, size, perms);
    return 3;
  }

  auto hypervisor = (t_hypervisor) handle;
  khash_t(memory) *memory = hypervisor->memory;
  int ret;
  for(uint64_t vaddr = address; vaddr < address + size; vaddr += HVF_PAGE_SIZE) {
    khiter_t k = kh_get(memory, memory, vaddr);
    if(k == kh_end(memory)) {
      fprintf(stderr, "mem_protect failed[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
      return 3;
    }
    t_memory_page page = kh_value(memory, k);
    page->perms = perms;
  }
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_write
 * Signature: (JIJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1write
  (JNIEnv *env, jclass clazz, jlong handle, jint index, jlong value) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  auto reg = (hv_reg_t) (HV_REG_X0 + index);
  HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(cpu->vcpu, reg, value));
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_set_sp64
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1set_1sp64
  (JNIEnv *env, jclass clazz, jlong handle, jlong value) {
  auto hypervisor = (t_hypervisor) handle;
  hypervisor->sp = value;
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_set_tpidr_el0
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1set_1tpidr_1el0
  (JNIEnv *env, jclass clazz, jlong handle, jlong value) {
  auto hypervisor = (t_hypervisor) handle;
  hypervisor->tpidr = value;
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_set_cpacr_el1
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1set_1cpacr_1el1
  (JNIEnv *env, jclass clazz, jlong handle, jlong value) {
  auto hypervisor = (t_hypervisor) handle;
  hypervisor->cpacr = value;
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_set_spsr_el1
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1set_1spsr_1el1
  (JNIEnv *env, jclass clazz, jlong handle, jlong value) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_SPSR_EL1, value));
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_set_elr_el1
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1set_1elr_1el1
  (JNIEnv *env, jclass clazz, jlong handle, jlong value) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_ELR_EL1, value));
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_set_tpidrro_el0
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1set_1tpidrro_1el0
  (JNIEnv *env, jclass clazz, jlong handle, jlong value) {
  auto hypervisor = (t_hypervisor) handle;
  hypervisor->tpidrro = value;
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_set_nzcv
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1set_1nzcv
  (JNIEnv *env, jclass clazz, jlong handle, jlong value) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_SPSR_EL1, value));
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_read_vector
 * Signature: (JI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1read_1vector
  (JNIEnv *env, jclass, jlong handle, jint index) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  auto reg = (hv_simd_fp_reg_t) (HV_SIMD_FP_REG_Q0 + index);
  hv_simd_fp_uchar16_t fp;
  HYP_ASSERT_SUCCESS(hv_vcpu_get_simd_fp_reg(cpu->vcpu, reg, &fp));
  jbyteArray bytes = env->NewByteArray(16);
  auto *src = (jbyte *)&fp;
  env->SetByteArrayRegion(bytes, 0, 16, src);
  return bytes;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_set_vector
 * Signature: (JI[B)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1set_1vector
  (JNIEnv *env, jclass clazz, jlong handle, jint index, jbyteArray vector) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  jbyte *bytes = env->GetByteArrayElements(vector, nullptr);
  hv_simd_fp_uchar16_t fp;
  memcpy(&fp, bytes, 16);
  auto reg = (hv_simd_fp_reg_t) (HV_SIMD_FP_REG_Q0 + index);
  HYP_ASSERT_SUCCESS(hv_vcpu_set_simd_fp_reg(cpu->vcpu, reg, fp));
  env->ReleaseByteArrayElements(vector, bytes, JNI_ABORT);
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    mem_write
 * Signature: (JJ[B)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_mem_1write
  (JNIEnv *env, jclass clazz, jlong handle, jlong address, jbyteArray bytes) {
  jsize size = env->GetArrayLength(bytes);
  jbyte *data = env->GetByteArrayElements(bytes, nullptr);
  auto hypervisor = (t_hypervisor) handle;
  khash_t(memory) *memory = hypervisor->memory;
  char *src = (char *)data;
  uint64_t vaddr_end = address + size;
  for(uint64_t vaddr = address & ~HVF_PAGE_MASK; vaddr < vaddr_end; vaddr += HVF_PAGE_SIZE) {
    uint64_t start = vaddr < address ? address - vaddr : 0;
    uint64_t end = vaddr + HVF_PAGE_SIZE <= vaddr_end ? HVF_PAGE_SIZE : (vaddr_end - vaddr);
    uint64_t len = end - start;
    char *addr = get_memory_page(memory, vaddr, hypervisor->num_page_table_entries, hypervisor->page_table);
    if(addr == nullptr) {
      fprintf(stderr, "mem_write failed[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
      return 1;
    }
    char *dest = &addr[start];
//    printf("mem_write address=%p, vaddr=%p, start=%ld, len=%ld, addr=%p, dest=%p\n", (void*)address, (void*)vaddr, start, len, addr, dest);
    memcpy(dest, src, len);
    src += len;
  }
  env->ReleaseByteArrayElements(bytes, data, JNI_ABORT);
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    mem_read
 * Signature: (JJI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_mem_1read
  (JNIEnv *env, jclass clazz, jlong handle, jlong address, jint size) {
  auto hypervisor = (t_hypervisor) handle;
  khash_t(memory) *memory = hypervisor->memory;
  jbyteArray bytes = env->NewByteArray(size);
  uint64_t dest = 0;
  uint64_t vaddr_end = address + size;
  for(uint64_t vaddr = address & ~HVF_PAGE_MASK; vaddr < vaddr_end; vaddr += HVF_PAGE_SIZE) {
    uint64_t start = vaddr < address ? address - vaddr : 0;
    uint64_t end = vaddr + HVF_PAGE_SIZE <= vaddr_end ? HVF_PAGE_SIZE : (vaddr_end - vaddr);
    uint64_t len = end - start;
    char *addr = get_memory_page(memory, vaddr, hypervisor->num_page_table_entries, hypervisor->page_table);
    if(addr == nullptr) {
      fprintf(stderr, "mem_read failed[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
      return nullptr;
    }
    auto *src = (jbyte *)&addr[start];
    env->SetByteArrayRegion(bytes, (jsize) dest, (jsize) len, src);
    dest += len;
  }
  return bytes;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_read
 * Signature: (JI)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1read
  (JNIEnv *env, jclass clazz, jlong handle, jint index) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  uint64_t value = 0;
  auto reg = (hv_reg_t) (HV_REG_X0 + index);
  HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(cpu->vcpu, reg, &value));
  return (jlong) value;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_read_sp64
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1read_1sp64
  (JNIEnv *env, jclass clazz, jlong handle) {
  auto hypervisor = (t_hypervisor) handle;
  return (jlong) hypervisor->sp;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_read_pc64
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1read_1pc64
  (JNIEnv *env, jclass clazz, jlong handle) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  uint64_t pc = 0;
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_ELR_EL1, &pc));
  return (jlong) pc;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_read_nzcv
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1read_1nzcv
  (JNIEnv *env, jclass clazz, jlong handle) {
  auto hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  uint64_t cpsr = 0;
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_SPSR_EL1, &cpsr));
  return (jlong) cpsr;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    context_restore
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_context_1restore
  (JNIEnv *env, jclass clazz, jlong handle, jlong context) {
  auto hypervisor = (t_hypervisor) handle;
  auto ctx = (t_cpu_context) context;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  t_vcpu_context vcpu_context = get_vcpu_context(cpu);
  memcpy(vcpu_context, &ctx->ctx, sizeof(struct vcpu_context));
  hypervisor->sp = ctx->sp;
  hypervisor->cpacr = ctx->cpacr;
  hypervisor->tpidr = ctx->tpidr;
  hypervisor->tpidrro = ctx->tpidrro;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    context_save
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_context_1save
  (JNIEnv *env, jclass clazz, jlong handle, jlong context) {
  auto hypervisor = (t_hypervisor) handle;
  auto ctx = (t_cpu_context) context;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(env, hypervisor);
  t_vcpu_context vcpu_context = get_vcpu_context(cpu);
  memcpy(&ctx->ctx, vcpu_context, sizeof(struct vcpu_context));
  ctx->sp = hypervisor->sp;
  ctx->cpacr = hypervisor->cpacr;
  ctx->tpidr = hypervisor->tpidr;
  ctx->tpidrro = hypervisor->tpidrro;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    context_alloc
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_context_1alloc
  (JNIEnv *env, jclass clazz) {
  void *ctx = malloc(sizeof(struct cpu_context));
  return (jlong) ctx;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_free
  (JNIEnv *env, jclass clazz, jlong context) {
  void *ctx = (void *) context;
  free(ctx);
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_read_cpacr_el1
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1read_1cpacr_1el1
  (JNIEnv *env, jclass clazz, jlong handle) {
  auto hypervisor = (t_hypervisor) handle;
  return (jlong) hypervisor->cpacr;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    emu_stop
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_emu_1stop
  (JNIEnv *env, jclass clazz, jlong handle) {
  auto hypervisor = (t_hypervisor) handle;
  hypervisor->stop_request = true;
  return 0;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  JNIEnv *env;
  if (JNI_OK != vm->GetEnv((void **)&env, JNI_VERSION_1_6)) {
    return JNI_ERR;
  }
  jclass cHypervisorCallback = env->FindClass("com/github/unidbg/arm/backend/hypervisor/HypervisorCallback");
  if (env->ExceptionCheck()) {
    return JNI_ERR;
  }
  handleException = env->GetMethodID(cHypervisorCallback, "handleException", "(JJJJ)Z");
  handleUnknownException = env->GetMethodID(cHypervisorCallback, "handleUnknownException", "(IJJJ)V");

  return JNI_VERSION_1_6;
}
