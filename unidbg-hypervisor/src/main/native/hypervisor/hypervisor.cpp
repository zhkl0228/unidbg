#include <assert.h>
#include <sys/mman.h>
#include <sys/errno.h>

#include <Hypervisor/Hypervisor.h>

#include "hypervisor.h"

typedef struct hypervisor {
  bool is64Bit;
  khash_t(memory) *memory;
  size_t num_page_table_entries;
  void **page_table;
} *t_hypervisor;

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
 * Method:    createVM
 * Signature: (Z)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_createVM
  (JNIEnv *env, jclass clazz, jboolean is64Bit) {
  // Create the VM
  HYP_ASSERT_SUCCESS(hv_vm_create(NULL));

  uint32_t max_vcpu_count = 0;
  HYP_ASSERT_SUCCESS(hv_vm_get_max_vcpu_count(&max_vcpu_count));
  printf("createVM max_vcpu_count=%u\n", max_vcpu_count);

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
  return (jlong) hypervisor;
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
    kh_value(memory, k) = page;

    HYP_ASSERT_SUCCESS(hv_vm_map(addr, vaddr, PAGE_SIZE, perms));
  }
  return 0;
}
