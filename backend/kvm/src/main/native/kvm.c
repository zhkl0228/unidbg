#include <assert.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/errno.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/kvm.h>

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "kvm.h"

typedef struct kvm {
  bool is64Bit;
  khash_t(memory) *memory;
  size_t num_page_table_entries;
  void **page_table;
  pthread_key_t cpu_key;
  jobject callback;
  bool stop_request;
} *t_kvm;

typedef struct kvm_cpu {
  int fd;
} *t_kvm_cpu;

static void destroy_kvm_cpu(void *data) {
  printf("destroy_kvm_cpu data=%p\n", data);
  t_kvm_cpu cpu = (t_kvm_cpu) data;
  close(cpu->fd);
  free(cpu);
}

static int gKvmFd = 0;
static int gRunSize = 0;

__attribute__((constructor))
static void init() {
  int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
  if(kvm == -1) {
    fprintf(stderr, "open /dev/kvm failed.\n");
    abort();
    return;
  }

  int ret = ioctl(kvm, KVM_GET_API_VERSION, NULL);
  if(ret != 12) {
    fprintf(stderr, "kvm version not supported: %d\n", ret);
    abort();
    return;
  }

  ret = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
  if (!ret) {
    fprintf(stderr, "kvm user memory capability unavailable\n");
    abort();
    return;
  }

  gRunSize = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
  int fd = ioctl(kvm, KVM_CREATE_VM, 0UL);
  if (fd == -1) {
    fprintf(stderr, "createVM failed\n");
    abort();
    return;
  }
  close(kvm);
  gKvmFd = fd;
  printf("initVM fd=%d, gRunSize=%d\n", fd, gRunSize);
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
  for (khiter_t k = kh_begin(memory); k < kh_end(memory); k++) {
    if(kh_exist(memory, k)) {
      t_memory_page page = kh_value(memory, k);
//      HYP_ASSERT_SUCCESS(hv_vm_unmap(page->ipa, KVM_PAGE_SIZE));
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
