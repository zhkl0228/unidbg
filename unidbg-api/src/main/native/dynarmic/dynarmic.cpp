#include <array>
#include <cstdint>
#include <cstdio>
#include <exception>

#include <dynarmic/A32/a32.h>
#include <dynarmic/A32/config.h>

#include <dynarmic/A64/a64.h>
#include <dynarmic/A64/config.h>

#include <sys/mman.h>
#include "dynarmic.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    nativeInitialize
 * Signature: (Z)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_nativeInitialize
  (JNIEnv *env, jclass clazz, jboolean is64Bit) {
  t_dynarmic dynarmic = (t_dynarmic) calloc(1, sizeof(struct dynarmic));
  dynarmic->is64Bit = is64Bit == JNI_TRUE;
  dynarmic->memory = kh_init(memory);
  return (jlong) dynarmic;
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    nativeDestroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_nativeDestroy
  (JNIEnv *env, jclass clazz, jlong handle) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  khash_t(memory) *memory = dynarmic->memory;
  for (khiter_t k = kh_begin(memory); k < kh_end(memory); k++) {
    if(kh_exist(memory, k)) {
      t_memory_page page = kh_value(memory, k);
      int ret = munmap(page->addr, PAGE_SIZE);
      if(ret != 0) {
        fprintf(stderr, "munmap failed[%s->%s:%d]: addr=%p, ret=%d\n", __FILE__, __func__, __LINE__, page->addr, ret);
      }
      free(page);
    }
  }
  kh_destroy(memory, memory);
  free(dynarmic);
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    mem_map
 * Signature: (JJJI)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_mem_1map
  (JNIEnv *env, jclass clazz, jlong handle, jlong address, jlong size, jint perms) {
  if(address & PAGE_MASK) {
    return 1;
  }
  if(size == 0 || (size & PAGE_MASK)) {
    return 2;
  }
  t_dynarmic dynarmic = (t_dynarmic) handle;
  khash_t(memory) *memory = dynarmic->memory;
  int ret;
  for(long vaddr = address; vaddr < address + size; vaddr += PAGE_SIZE) {
    if(kh_get(memory, memory, vaddr) != kh_end(memory)) {
      fprintf(stderr, "mem_map failed[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
      return 3;
    }
    void *addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(addr == MAP_FAILED) {
      fprintf(stderr, "mmap failed[%s->%s:%d]: addr=%p\n", __FILE__, __func__, __LINE__, (void*)addr);
      return 4;
    }
    khiter_t k = kh_put(memory, memory, vaddr, &ret);
    t_memory_page page = (t_memory_page) calloc(1, sizeof(struct memory_page));
    page->addr = addr;
    page->perms = perms;
    kh_value(memory, k) = page;
  }
  return 0;
}

#ifdef __cplusplus
}
#endif
