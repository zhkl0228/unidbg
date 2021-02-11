#include <assert.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/errno.h>

#include <fcntl.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <unistd.h>

#include "kvm.h"

typedef struct kvm_cpu {
  int fd;
  struct kvm_run *run;
} *t_kvm_cpu;

static int check_one_reg(uint64_t reg, int ret) {
  if(ret == 0) {
    return 0;
  }
  switch(errno) {
    case ENOENT:
      fprintf(stderr, "no such register: reg=0x%llx\n", reg);
      break;
    case EINVAL:
      fprintf(stderr, "invalid register ID, or no such register: reg=0x%llx\n", reg);
      break;
    case EPERM:
      fprintf(stderr, "(arm64) register access not allowed before vcpu finalization: reg=0x%llx\n", reg);
      break;
    default:
      fprintf(stderr, "unknown error: reg=0x%llx, errno=%d\n", reg, errno);
      break;
  }
  return ret;
}

hv_return_t hv_vcpu_get_reg(hv_vcpu_t vcpu, hv_reg_t reg, uint64_t *value) {
    struct kvm_one_reg reg_req = {
        .id = reg,
        .addr = (uint64_t)value,
    };
    if (check_one_reg(reg, ioctl(vcpu->fd, KVM_GET_ONE_REG, &reg_req)) < 0) {
        return -1;
    }
    return HV_SUCCESS;
}

hv_return_t hv_vcpu_set_reg(hv_vcpu_t vcpu, hv_reg_t reg, uint64_t value) {
    struct kvm_one_reg reg_req = {
        .id = reg,
        .addr = (uint64_t)&value,
    };
    if (check_one_reg(reg, ioctl(vcpu->fd, KVM_SET_ONE_REG, &reg_req)) < 0) {
        return -1;
    }
    return HV_SUCCESS;
}

hv_return_t hv_vcpu_get_sys_reg(hv_vcpu_t vcpu, hv_sys_reg_t reg, uint64_t *value) {
    struct kvm_one_reg reg_req = {
        .id = reg,
        .addr = (uint64_t)value,
    };
    if (check_one_reg(reg, ioctl(vcpu->fd, KVM_GET_ONE_REG, &reg_req)) < 0) {
        return -1;
    }
    return HV_SUCCESS;
}

hv_return_t hv_vcpu_set_sys_reg(hv_vcpu_t vcpu, hv_sys_reg_t reg, uint64_t value) {
    struct kvm_one_reg reg_req = {
        .id = reg,
        .addr = (uint64_t)&value,
    };
    if (check_one_reg(reg, ioctl(vcpu->fd, KVM_SET_ONE_REG, &reg_req)) < 0) {
        return -1;
    }
    return HV_SUCCESS;
}

hv_return_t hv_vcpu_get_simd_fp_reg(hv_vcpu_t vcpu, hv_simd_fp_reg_t reg, hv_simd_fp_uchar16_t *value) {
    struct kvm_one_reg reg_req = {
        .id = reg,
        .addr = (uint64_t)value,
    };
    if (check_one_reg(reg, ioctl(vcpu->fd, KVM_GET_ONE_REG, &reg_req)) < 0) {
        return -1;
    }
    return HV_SUCCESS;
}

hv_return_t hv_vcpu_set_simd_fp_reg(hv_vcpu_t vcpu, hv_simd_fp_reg_t reg, hv_simd_fp_uchar16_t value) {
    struct kvm_one_reg reg_req = {
        .id = reg,
        .addr = (uint64_t)&value,
    };
    if (check_one_reg(reg, ioctl(vcpu->fd, KVM_SET_ONE_REG, &reg_req)) < 0) {
        return -1;
    }
    return HV_SUCCESS;
}

static int gKvmFd = 0;
static int gRunSize = 0;
static int gMaxSlots = 0;

/*
 * Class:     com_github_unidbg_arm_backend_kvm_Kvm
 * Method:    getMaxSlots
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_kvm_Kvm_getMaxSlots
  (JNIEnv *env, jclass clazz) {
  return gMaxSlots;
}

/*
 * Class:     com_github_unidbg_arm_backend_kvm_Kvm
 * Method:    getPageSize
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_kvm_Kvm_getPageSize
  (JNIEnv *env, jclass clazz) {
  long sz = sysconf(_SC_PAGESIZE);
  return (jint) sz;
}

typedef struct kvm {
  bool is64Bit;
  khash_t(memory) *memory;
  size_t num_page_table_entries;
  void **page_table;
  pthread_key_t cpu_key;
  jobject callback;
  bool stop_request;
} *t_kvm;

static t_kvm_cpu get_kvm_cpu(JNIEnv *env, t_kvm kvm) {
  t_kvm_cpu cpu = (t_kvm_cpu) pthread_getspecific(kvm->cpu_key);
  if(cpu) {
    return cpu;
  } else {
    cpu = (t_kvm_cpu) calloc(1, sizeof(struct kvm_cpu));
    int fd = ioctl(gKvmFd, KVM_CREATE_VCPU, 0);
    if (fd == -1) {
      fprintf(stderr, "KVM_CREATE_VCPU failed.\n");
      abort();
      return NULL;
    }
    struct kvm_vcpu_init vcpu_init;
    if (ioctl(gKvmFd, KVM_ARM_PREFERRED_TARGET, &vcpu_init) == -1) {
      fprintf(stderr, "KVM_ARM_PREFERRED_TARGET failed.\n");
      abort();
      return NULL;
    }
    // ask for psci 0.2
    vcpu_init.features[0] |= 1ul << KVM_ARM_VCPU_PSCI_0_2;
    if (ioctl(fd, KVM_ARM_VCPU_INIT, &vcpu_init) == -1) {
      fprintf(stderr, "KVM_ARM_VCPU_INIT failed.\n");
      abort();
      return NULL;
    }
    struct kvm_run *run = mmap(NULL, gRunSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (run == MAP_FAILED) {
      fprintf(stderr, "init kvm_run failed.\n");
      abort();
      return NULL;
    }
    cpu->fd = fd;
    cpu->run = run;

    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu, HV_SYS_REG_VBAR_EL1, REG_VBAR_EL1));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu, HV_SYS_REG_SCTLR_EL1, 0x4c5d864));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu, HV_SYS_REG_CNTV_CVAL_EL0, 0x0));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu, HV_SYS_REG_CNTV_CTL_EL0, 0x0));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu, HV_SYS_REG_CNTKCTL_EL1, 0x0));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu, HV_SYS_REG_MIDR_EL1, 0x410fd083));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu, HV_SYS_REG_ID_AA64MMFR0_EL1, 0x5));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(cpu, HV_SYS_REG_ID_AA64MMFR2_EL1, 0x10000));
    assert(pthread_setspecific(kvm->cpu_key, cpu) == 0);

    if(kvm->is64Bit) {
//      vcpu->HV_SYS_REG_HCR_EL2 |= (1LL << HCR_EL2$DC); // set stage 1 as normal memory
      return cpu;
    } else {
      abort();
    }

    return cpu;
  }
}

static void destroy_kvm_cpu(void *data) {
  printf("destroy_kvm_cpu data=%p\n", data);
  t_kvm_cpu cpu = (t_kvm_cpu) data;
  munmap(cpu->run, gRunSize);
  close(cpu->fd);
  free(cpu);
}

__attribute__((constructor))
static void init() {
  int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
  if(kvm == -1) {
    fprintf(stderr, "open /dev/kvm failed.\n");
    abort();
    return;
  }

  int api_ver = ioctl(kvm, KVM_GET_API_VERSION, NULL);
  if(api_ver != KVM_API_VERSION) {
    fprintf(stderr, "Got KVM api version %d, expected %d\n", api_ver, KVM_API_VERSION);
    abort();
    return;
  }

  int ret = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
  if (!ret) {
    fprintf(stderr, "kvm user memory capability unavailable\n");
    abort();
    return;
  }

  gRunSize = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
  gMaxSlots = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_NR_MEMSLOTS);
  int address_space = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_MULTI_ADDRESS_SPACE);

  int fd = ioctl(kvm, KVM_CREATE_VM, 0UL);
  if (fd == -1) {
    fprintf(stderr, "createVM failed\n");
    abort();
    return;
  }
  close(kvm);
  gKvmFd = fd;

  printf("initVM fd=%d, gRunSize=0x%x, gMaxSlots=0x%x, address_space=0x%x\n", fd, gRunSize, gMaxSlots, address_space);
  printf("initVM HV_REG_X0=0x%llx, HV_REG_X1=0x%llx, HV_REG_PC=0x%llx\n", HV_REG_X0, HV_REG_X1, HV_REG_PC);
}

__attribute__((destructor))
static void destroy() {
  close(gKvmFd);
  gKvmFd = 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_kvm_Kvm
 * Method:    nativeInitialize
 * Signature: (Z)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_kvm_Kvm_nativeInitialize
  (JNIEnv *env, jclass clazz, jboolean is64Bit) {
  t_kvm kvm = (t_kvm) calloc(1, sizeof(struct kvm));
  if(kvm == NULL) {
    fprintf(stderr, "calloc kvm failed: size=%lu\n", sizeof(struct kvm));
    abort();
    return 0;
  }
  kvm->is64Bit = is64Bit == JNI_TRUE;
  kvm->memory = kh_init(memory);
  if(kvm->memory == NULL) {
    fprintf(stderr, "kh_init memory failed\n");
    abort();
    return 0;
  }
  int ret = kh_resize(memory, kvm->memory, 0x1000);
  if(ret == -1) {
    fprintf(stderr, "kh_resize memory failed\n");
    abort();
    return 0;
  }
  kvm->num_page_table_entries = 1ULL << (PAGE_TABLE_ADDRESS_SPACE_BITS - PAGE_BITS);
  size_t size = kvm->num_page_table_entries * sizeof(void*);
  kvm->page_table = (void **)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if(kvm->page_table == MAP_FAILED) {
    fprintf(stderr, "createVM mmap failed[%s->%s:%d] size=0x%zx, errno=%d, msg=%s\n", __FILE__, __func__, __LINE__, size, errno, strerror(errno));
    abort();
    return 0;
  }
  assert(pthread_key_create(&kvm->cpu_key, destroy_kvm_cpu) == 0);
  return (jlong) kvm;
}

/*
 * Class:     com_github_unidbg_arm_backend_kvm_Kvm
 * Method:    nativeDestroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_kvm_Kvm_nativeDestroy
  (JNIEnv *env, jclass clazz, jlong handle) {
  t_kvm kvm = (t_kvm) handle;
  khash_t(memory) *memory = kvm->memory;
  khiter_t k = kh_begin(memory);
  for (; k < kh_end(memory); k++) {
    if(kh_exist(memory, k)) {
      t_memory_page page = kh_value(memory, k);
      int ret = munmap(page->addr, KVM_PAGE_SIZE);
      if(ret != 0) {
        fprintf(stderr, "munmap failed[%s->%s:%d]: addr=%p, ret=%d\n", __FILE__, __func__, __LINE__, page->addr, ret);
      }
      free(page);
    }
  }
  kh_destroy(memory, memory);
  if(kvm->callback) {
    (*env)->DeleteGlobalRef(env, kvm->callback);
  }
  if(kvm->page_table) {
    int ret = munmap(kvm->page_table, kvm->num_page_table_entries * sizeof(void*));
    if(ret != 0) {
      fprintf(stderr, "munmap failed[%s->%s:%d]: page_table=%p, ret=%d\n", __FILE__, __func__, __LINE__, kvm->page_table, ret);
    }
  }
  free(kvm);
}

/*
 * Class:     com_github_unidbg_arm_backend_kvm_Kvm
 * Method:    set_user_memory_region
 * Signature: (JIJJ)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_kvm_Kvm_set_1user_1memory_1region
  (JNIEnv *env, jclass clazz, jlong handle, jint slot, jlong guest_phys_addr, jlong memory_size) {
  t_kvm kvm = (t_kvm) handle;
  khash_t(memory) *memory = kvm->memory;

  char *start_addr = (char *) mmap(NULL, memory_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if(start_addr == MAP_FAILED) {
    fprintf(stderr, "mmap failed[%s->%s:%d]: start_addr=%p\n", __FILE__, __func__, __LINE__, start_addr);
    abort();
    return 0L;
  }

  struct kvm_userspace_memory_region region = {
    .slot = slot,
    .flags = 0,
    .guest_phys_addr = guest_phys_addr,
    .memory_size = memory_size,
    .userspace_addr = (uint64_t)start_addr,
  };
  if (ioctl(gKvmFd, KVM_SET_USER_MEMORY_REGION, &region) == -1) {
    fprintf(stderr, "set_user_memory_region failed start_addr=%p, guest_phys_addr=0x%lx\n", start_addr, guest_phys_addr);
    abort();
    return 0L;
  }

  int ret;
  uint64_t vaddr = guest_phys_addr;
  for(; vaddr < guest_phys_addr + memory_size; vaddr += KVM_PAGE_SIZE) {
    uint64_t idx = vaddr >> PAGE_BITS;
    if(kh_get(memory, memory, vaddr) != kh_end(memory)) {
      fprintf(stderr, "set_user_memory_region failed[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
      abort();
      return 0L;
    }

    void *addr = &start_addr[vaddr - guest_phys_addr];
    if(kvm->page_table && idx < kvm->num_page_table_entries) {
      kvm->page_table[idx] = addr;
    } else {
      fprintf(stderr, "guest_phys_addr warning[%s->%s:%d]: addr=%p, page_table=%p, idx=%llu, num_page_table_entries=%zu\n", __FILE__, __func__, __LINE__, (void*)addr, kvm->page_table, idx, kvm->num_page_table_entries);
    }
    khiter_t k = kh_put(memory, memory, vaddr, &ret);
    t_memory_page page = (t_memory_page) calloc(1, sizeof(struct memory_page));
    if(page == NULL) {
      fprintf(stderr, "calloc page failed: size=%lu\n", sizeof(struct memory_page));
      abort();
      return 0L;
    }
    page->addr = addr;
    kh_value(memory, k) = page;
  }

  return (jlong) start_addr;
}

/*
 * Class:     com_github_unidbg_arm_backend_kvm_Kvm
 * Method:    reg_read_cpacr_el1
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_kvm_Kvm_reg_1read_1cpacr_1el1
  (JNIEnv *env, jclass clazz, jlong handle) {
  t_kvm kvm = (t_kvm) handle;
  t_kvm_cpu cpu = get_kvm_cpu(env, kvm);
  uint64_t cpacr = 0;
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(cpu, HV_SYS_REG_CPACR_EL1, &cpacr));
  return cpacr;
}
