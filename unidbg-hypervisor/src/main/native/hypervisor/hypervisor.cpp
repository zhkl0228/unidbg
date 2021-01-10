#include <assert.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/errno.h>

#include "hypervisor.h"

typedef struct hypervisor {
  bool is64Bit;
  khash_t(memory) *memory;
  size_t num_page_table_entries;
  void **page_table;
  pthread_key_t cpu_key;
} *t_hypervisor;

static char *get_memory_page(khash_t(memory) *memory, uint64_t vaddr, size_t num_page_table_entries, void **page_table) {
    uint64_t idx = vaddr >> PAGE_BITS;
    if(page_table && idx < num_page_table_entries) {
      return (char *)page_table[idx];
    }
    uint64_t base = vaddr & ~PAGE_MASK;
    khiter_t k = kh_get(memory, memory, base);
    if(k == kh_end(memory)) {
      return NULL;
    }
    t_memory_page page = kh_value(memory, k);
    return (char *)page->addr;
}

static inline void *get_memory(khash_t(memory) *memory, uint64_t vaddr, size_t num_page_table_entries, void **page_table) {
    char *page = get_memory_page(memory, vaddr, num_page_table_entries, page_table);
    return page ? &page[vaddr & PAGE_MASK] : NULL;
}

typedef struct hypervisor_cpu {
  hv_vcpu_t vcpu;
  hv_vcpu_exit_t *vcpu_exit;
} *t_hypervisor_cpu;

static t_hypervisor_cpu get_hypervisor_cpu(t_hypervisor hypervisor) {
  t_hypervisor_cpu cpu = (t_hypervisor_cpu) pthread_getspecific(hypervisor->cpu_key);
  if(cpu) {
    return cpu;
  } else {
    cpu = (t_hypervisor_cpu) calloc(1, sizeof(struct hypervisor_cpu));
    HYP_ASSERT_SUCCESS(hv_vcpu_create(&cpu->vcpu, &cpu->vcpu_exit, NULL));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_VBAR_EL1, REG_VBAR_EL1));
    // Trap debug access (BRK)
    HYP_ASSERT_SUCCESS(hv_vcpu_set_trap_debug_exceptions(cpu->vcpu, true));
    assert(pthread_setspecific(hypervisor->cpu_key, cpu) == 0);
    printf("create_hypervisor_cpu=%p\n", cpu);
    return cpu;
  }
}

static void destroy_hypervisor_cpu(void *data) {
  printf("destroy_hypervisor_cpu data=%p\n", data);
  t_hypervisor_cpu cpu = (t_hypervisor_cpu) data;
  HYP_ASSERT_SUCCESS(hv_vcpu_destroy(cpu->vcpu));
  free(cpu);
}

__attribute__((constructor))
static void init() {
  HYP_ASSERT_SUCCESS(hv_vm_create(NULL));
}

__attribute__((destructor))
static void destroy() {
  HYP_ASSERT_SUCCESS(hv_vm_destroy());
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    setHypervisorCallback
 * Signature: (JLcom/github/unidbg/arm/backend/hypervisor/HypervisorCallback;)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_setHypervisorCallback
  (JNIEnv *env, jclass clazz, jlong handle, jobject callback) {
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    nativeInitialize
 * Signature: (Z)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_nativeInitialize
  (JNIEnv *env, jclass clazz, jboolean is64Bit) {
  t_hypervisor hypervisor = (t_hypervisor) calloc(1, sizeof(struct hypervisor));
  if(hypervisor == NULL) {
    fprintf(stderr, "calloc hypervisor failed: size=%lu\n", sizeof(struct hypervisor));
    abort();
    return 0;
  }
  hypervisor->is64Bit = is64Bit == JNI_TRUE;
  hypervisor->memory = kh_init(memory);
  if(hypervisor->memory == NULL) {
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
  hypervisor->page_table = (void **)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
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
  t_hypervisor hypervisor = (t_hypervisor) handle;
  khash_t(memory) *memory = hypervisor->memory;
  for (khiter_t k = kh_begin(memory); k < kh_end(memory); k++) {
    if(kh_exist(memory, k)) {
      t_memory_page page = kh_value(memory, k);
      HYP_ASSERT_SUCCESS(hv_vm_unmap(page->ipa, PAGE_SIZE));
      int ret = munmap(page->addr, PAGE_SIZE);
      if(ret != 0) {
        fprintf(stderr, "munmap failed[%s->%s:%d]: addr=%p, ret=%d\n", __FILE__, __func__, __LINE__, page->addr, ret);
      }
      free(page);
    }
  }
  kh_destroy(memory, memory);
  if(hypervisor->page_table) {
    int ret = munmap(hypervisor->page_table, hypervisor->num_page_table_entries * sizeof(void*));
    if(ret != 0) {
      fprintf(stderr, "munmap failed[%s->%s:%d]: page_table=%p, ret=%d\n", __FILE__, __func__, __LINE__, hypervisor->page_table, ret);
    }
  }
  assert(pthread_key_delete(hypervisor->cpu_key) == 0);
  free(hypervisor);
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    mem_map
 * Signature: (JJJI)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_mem_1map
  (JNIEnv *env, jclass clazz, jlong handle, jlong address, jlong size, jint perms) {
  if(address & PAGE_MASK) {
    return 1;
  }
  if(size == 0 || (size & PAGE_MASK)) {
    return 2;
  }
  t_hypervisor hypervisor = (t_hypervisor) handle;
  khash_t(memory) *memory = hypervisor->memory;
  int ret;
  for(uint64_t vaddr = address; vaddr < address + size; vaddr += PAGE_SIZE) {
    uint64_t idx = vaddr >> PAGE_BITS;
    if(kh_get(memory, memory, vaddr) != kh_end(memory)) {
      fprintf(stderr, "mem_map failed[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
      return 3;
    }

    void *addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(addr == MAP_FAILED) {
      fprintf(stderr, "mmap failed[%s->%s:%d]: addr=%p\n", __FILE__, __func__, __LINE__, (void*)addr);
      return 4;
    }
    if(hypervisor->page_table && idx < hypervisor->num_page_table_entries) {
      hypervisor->page_table[idx] = addr;
    } else {
      // 0xffffff80001f0000ULL: 0x10000
    }
    khiter_t k = kh_put(memory, memory, vaddr, &ret);
    t_memory_page page = (t_memory_page) calloc(1, sizeof(struct memory_page));
    if(page == NULL) {
      fprintf(stderr, "calloc page failed: size=%lu\n", sizeof(struct memory_page));
      abort();
      return 0;
    }
    page->addr = addr;
    page->perms = perms;
    page->ipa = vaddr;
    kh_value(memory, k) = page;

    if(0x40ae81d0 >= page->ipa && 0x40ae81d0 < page->ipa + PAGE_SIZE) {
      printf("hv_vm_map addr=%p, ipa=0x%llx, size=0x%lx, perms=0x%x\n", addr, page->ipa, size, perms);
    }
    HYP_ASSERT_SUCCESS(hv_vm_map(addr, page->ipa, PAGE_SIZE, perms));
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
  t_hypervisor hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(hypervisor);
  hv_reg_t reg = (hv_reg_t) (HV_REG_X0 + index);
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
  t_hypervisor hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(hypervisor);
  HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_REG_SP, value));
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_set_tpidr_el0
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1set_1tpidr_1el0
  (JNIEnv *env, jclass clazz, jlong handle, jlong value) {
  t_hypervisor hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(hypervisor);
  HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_TPIDR_EL0, value));
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_set_cpacr_el1
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1set_1cpacr_1el1
  (JNIEnv *env, jclass clazz, jlong handle, jlong value) {
  t_hypervisor hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(hypervisor);
  HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_CPACR_EL1, value));
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
  jbyte *data = env->GetByteArrayElements(bytes, NULL);
  t_hypervisor hypervisor = (t_hypervisor) handle;
  khash_t(memory) *memory = hypervisor->memory;
  char *src = (char *)data;
  uint64_t vaddr_end = address + size;
  for(uint64_t vaddr = address & ~PAGE_MASK; vaddr < vaddr_end; vaddr += PAGE_SIZE) {
    uint64_t start = vaddr < address ? address - vaddr : 0;
    uint64_t end = vaddr + PAGE_SIZE <= vaddr_end ? PAGE_SIZE : (vaddr_end - vaddr);
    uint64_t len = end - start;
    char *addr = get_memory_page(memory, vaddr, hypervisor->num_page_table_entries, hypervisor->page_table);
    if(addr == NULL) {
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
  t_hypervisor hypervisor = (t_hypervisor) handle;
  khash_t(memory) *memory = hypervisor->memory;
  jbyteArray bytes = env->NewByteArray(size);
  uint64_t dest = 0;
  uint64_t vaddr_end = address + size;
  for(uint64_t vaddr = address & ~PAGE_MASK; vaddr < vaddr_end; vaddr += PAGE_SIZE) {
    uint64_t start = vaddr < address ? address - vaddr : 0;
    uint64_t end = vaddr + PAGE_SIZE <= vaddr_end ? PAGE_SIZE : (vaddr_end - vaddr);
    uint64_t len = end - start;
    char *addr = get_memory_page(memory, vaddr, hypervisor->num_page_table_entries, hypervisor->page_table);
    if(addr == NULL) {
      fprintf(stderr, "mem_read failed[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
      return NULL;
    }
    jbyte *src = (jbyte *)&addr[start];
    env->SetByteArrayRegion(bytes, dest, len, src);
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
  t_hypervisor hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(hypervisor);
  uint64_t value = 0;
  hv_reg_t reg = (hv_reg_t) (HV_REG_X0 + index);
  HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(cpu->vcpu, reg, &value));
  return value;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_read_sp64
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1read_1sp64
  (JNIEnv *env, jclass clazz, jlong handle) {
  t_hypervisor hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(hypervisor);
  uint64_t sp = 0;
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_REG_SP, &sp));
  return sp;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_read_pc64
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1read_1pc64
  (JNIEnv *env, jclass clazz, jlong handle) {
  t_hypervisor hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(hypervisor);
  uint64_t pc = 0;
  HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(cpu->vcpu, HV_REG_PC, &pc));
  return pc;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_read_nzcv
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1read_1nzcv
  (JNIEnv *env, jclass clazz, jlong handle) {
  t_hypervisor hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(hypervisor);
  uint64_t cpsr = 0;
  HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(cpu->vcpu, HV_REG_CPSR, &cpsr));
  return cpsr;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    reg_read_cpacr_el1
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_reg_1read_1cpacr_1el1
  (JNIEnv *env, jclass clazz, jlong handle) {
  t_hypervisor hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(hypervisor);
  uint64_t cpacr = 0;
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_CPACR_EL1, &cpacr));
  return cpacr;
}

static bool handle_exception_el1(t_hypervisor hypervisor, t_hypervisor_cpu cpu, uint64_t syndrome, uint64_t far) {
  bool advance_pc = false;
  uint32_t ec = syn_get_ec(syndrome);
  uint64_t elr;
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_ELR_EL1, &elr));
  fprintf(stderr, "handle_exception_el1 syndrome=0x%llx, far=0x%llx, ec=0x%x, ELR_EL1=0x%llx\n", syndrome, far, ec, elr);
  switch (ec) {
    case EC_DATAABORT: {
      bool isv = syndrome & ARM_EL_ISV;
      bool iswrite = (syndrome >> 6) & 1;
      bool s1ptw = (syndrome >> 7) & 1;
      uint32_t sas = (syndrome >> 22) & 3;
      uint32_t len = 1 << sas;
      uint32_t srt = (syndrome >> 16) & 0x1f;
      uint64_t vaddr = far;
      fprintf(stderr, "EC_DATAABORT isv=%d, iswrite=%d, s1ptw=%d, sas=%d, len=%d, srt=%d, vaddr=0x%llx\n", isv, iswrite, s1ptw, sas, len, srt, vaddr);
      if(isv == 0) {
        return false;
      }
      if(iswrite) {
        abort();
      } else {
        switch(len) {
          case 1:
            uint8_t *dest = (uint8_t *) get_memory(hypervisor->memory, vaddr, hypervisor->num_page_table_entries, hypervisor->page_table);
            if(dest) {
              assert(srt < 31);
              hv_reg_t reg = (hv_reg_t) (HV_REG_X0 + srt);
              HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(cpu->vcpu, reg, dest[0]));
            } else {
              fprintf(stderr, "MemoryRead8[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
              return false;
            }
            advance_pc = true;
            break;
        }
      }
      break;
    }
  }
  if(advance_pc) {
    uint64_t pc;
    HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_ELR_EL1, &pc));
    assert(hypervisor->is64Bit);
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu->vcpu, HV_SYS_REG_ELR_EL1, pc + 4));
  }
  return advance_pc;
}

static bool handle_exception(t_hypervisor hypervisor, t_hypervisor_cpu cpu) {
  uint64_t syndrome = cpu->vcpu_exit->exception.syndrome;
  uint32_t ec = syn_get_ec(syndrome);
  switch(ec) {
    case 0x16: { // Exception Class 0x16 is "HVC instruction execution in AArch64 state, when HVC is not disabled."
      uint64_t esr = 0;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_ESR_EL1, &esr));
      uint64_t far = 0;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_FAR_EL1, &far));
      return handle_exception_el1(hypervisor, cpu, esr, far);
    }
    default:
      uint64_t pc = 0;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_ELR_EL1, &pc));
      uint64_t cpsr = 0;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_SPSR_EL1, &cpsr));
      uint64_t sp = 0;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_SP_EL1, &sp));
      uint64_t esr = 0;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_ESR_EL1, &esr));
      uint64_t far = 0;
      HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu->vcpu, HV_SYS_REG_FAR_EL1, &far));
      fprintf(stderr, "Unexpected VM exception: 0x%llx, EC 0x%x, VirtAddr 0x%llx, IPA 0x%llx, ELR_EL1 0x%llx, SPSR_EL1 0x%llx, SP_EL1 0x%llx, ESR_EL1 0x%llx, FAR_EL1 0x%llx\n",
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

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    emu_start
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_emu_1start
  (JNIEnv *env, jclass clazz, jlong handle, jlong pc) {
  t_hypervisor hypervisor = (t_hypervisor) handle;
  t_hypervisor_cpu cpu = get_hypervisor_cpu(hypervisor);

  HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(cpu->vcpu, HV_REG_CPSR, 0x3c0));
  HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(cpu->vcpu, HV_REG_PC, pc));
  printf("emu_start pc=0x%lx\n", pc);
  while(true) {
    HYP_ASSERT_SUCCESS(hv_vcpu_run(cpu->vcpu));

    switch(cpu->vcpu_exit->reason) {
      case HV_EXIT_REASON_EXCEPTION: {
        if(handle_exception(hypervisor, cpu)) {
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
  }
  return 0;
}
