#include <array>
#include <cstdint>
#include <cstdio>
#include <exception>

#include <sys/mman.h>
#include "dynarmic.h"

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

class DynarmicCallbacks64 final : public Dynarmic::A64::UserCallbacks {
public:
    u8 MemoryRead8(u64 vaddr) override {
        fprintf(stderr, "MemoryRead8[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
        abort();
        return 0;
    }
    u16 MemoryRead16(u64 vaddr) override {
        fprintf(stderr, "MemoryRead16[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
        abort();
        return 0;
    }
    u32 MemoryRead32(u64 vaddr) override {
        fprintf(stderr, "MemoryRead32[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
        abort();
        return 0;
    }
    u64 MemoryRead64(u64 vaddr) override {
        fprintf(stderr, "MemoryRead64[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
        abort();
        return 0;
    }
    Dynarmic::A64::Vector MemoryRead128(u64 vaddr) override {
        return {MemoryRead64(vaddr), MemoryRead64(vaddr + 8)};
    }

    void MemoryWrite8(u64 vaddr, u8 value) override {
        fprintf(stderr, "MemoryWrite8[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
        abort();
    }
    void MemoryWrite16(u64 vaddr, u16 value) override {
        fprintf(stderr, "MemoryWrite16[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
        abort();
    }
    void MemoryWrite32(u64 vaddr, u32 value) override {
        fprintf(stderr, "MemoryWrite32[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
        abort();
    }
    void MemoryWrite64(u64 vaddr, u64 value) override {
        fprintf(stderr, "MemoryWrite64[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
        abort();
    }
    void MemoryWrite128(u64 vaddr, Dynarmic::A64::Vector value) override {
        MemoryWrite64(vaddr, value[0]);
        MemoryWrite64(vaddr + 8, value[1]);
    }

    bool MemoryWriteExclusive8(u64 vaddr, std::uint8_t value, std::uint8_t expected) override {
        fprintf(stderr, "MemoryWriteExclusive8[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
        abort();
        return false;
    }
    bool MemoryWriteExclusive16(u64 vaddr, std::uint16_t value, std::uint16_t expected) override {
        fprintf(stderr, "MemoryWriteExclusive16[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
        abort();
        return false;
    }
    bool MemoryWriteExclusive32(u64 vaddr, std::uint32_t value, std::uint32_t expected) override {
        fprintf(stderr, "MemoryWriteExclusive32[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
        abort();
        return false;
    }
    bool MemoryWriteExclusive64(u64 vaddr, std::uint64_t value, std::uint64_t expected) override {
        fprintf(stderr, "MemoryWriteExclusive64[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
        abort();
        return false;
    }
    bool MemoryWriteExclusive128(u64 vaddr, Dynarmic::A64::Vector value, Dynarmic::A64::Vector expected) override {
        fprintf(stderr, "MemoryWriteExclusive128[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
        abort();
        return false;
    }

    void InterpreterFallback(u64 pc, std::size_t num_instructions) override {
        fprintf(stderr, "InterpreterFallback[%s->%s:%d]: pc=%p, num_instructions=%lu\n", __FILE__, __func__, __LINE__, (void*)pc, num_instructions);
        abort();
    }

    void ExceptionRaised(u64 pc, Dynarmic::A64::Exception exception) override {
        fprintf(stderr, "ExceptionRaised[%s->%s:%d]: pc=%p, exception=%d\n", __FILE__, __func__, __LINE__, (void*)pc, exception);
        abort();
    }

    void CallSVC(u32 swi) override {
        fprintf(stderr, "CallSVC[%s->%s:%d]: swi=%d\n", __FILE__, __func__, __LINE__, swi);
        abort();
    }

    void AddTicks(u64 ticks) override {
    }

    u64 GetTicksRemaining() override {
        return (u64) -1;
    }

    u64 GetCNTPCT() override {
        return 0;
    }

    u64 tpidrro_el0 = 0;
    u64 tpidr_el0 = 0;
};

KHASH_MAP_INIT_INT64(memory, t_memory_page)

typedef struct dynarmic {
  bool is64Bit;
  khash_t(memory) *memory;
  std::shared_ptr<DynarmicCallbacks64> cb64;
  std::shared_ptr<Dynarmic::A64::Jit> jit64;
} *t_dynarmic;

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
  if(dynarmic->is64Bit) {
    std::shared_ptr<DynarmicCallbacks64> cb = std::make_shared<DynarmicCallbacks64>();
    DynarmicCallbacks64 *callbacks = cb.get();

    Dynarmic::A64::UserConfig config;
    config.callbacks = callbacks;
    config.tpidrro_el0 = &callbacks->tpidrro_el0;
    config.tpidr_el0 = &callbacks->tpidr_el0;
    dynarmic->cb64 = cb;
    dynarmic->jit64 = std::make_shared<Dynarmic::A64::Jit>(config);
  }
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
 * Method:    mem_unmap
 * Signature: (JJJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_mem_1unmap
  (JNIEnv *env, jclass clazz, jlong handle, jlong address, jlong size) {
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
    khiter_t k = kh_get(memory, memory, vaddr);
    if(k == kh_end(memory)) {
      fprintf(stderr, "mem_unmap failed[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
      return 3;
    }
    t_memory_page page = kh_value(memory, k);
    int ret = munmap(page->addr, PAGE_SIZE);
    if(ret != 0) {
      fprintf(stderr, "munmap failed[%s->%s:%d]: addr=%p, ret=%d\n", __FILE__, __func__, __LINE__, page->addr, ret);
    }
    free(page);
    kh_del(memory, memory, k);
  }
  return 0;
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

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    mem_protect
 * Signature: (JJJI)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_mem_1protect
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
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    mem_write
 * Signature: (JJ[B)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_mem_1write
  (JNIEnv *env, jclass clazz, jlong handle, jlong address, jbyteArray bytes) {
  jsize size = env->GetArrayLength(bytes);
  jbyte *data = env->GetByteArrayElements(bytes, NULL);
  t_dynarmic dynarmic = (t_dynarmic) handle;
  khash_t(memory) *memory = dynarmic->memory;
  char *src = (char *)data;
  long vaddr_end = address + size;
  for(long vaddr = address & ~PAGE_MASK; vaddr < vaddr_end; vaddr += PAGE_SIZE) {
    long start = vaddr < address ? address - vaddr : 0;
    long end = vaddr + PAGE_SIZE <= vaddr_end ? PAGE_SIZE : (vaddr_end - vaddr);
    long len = end - start;
    khiter_t k = kh_get(memory, memory, vaddr);
    if(k == kh_end(memory)) {
      fprintf(stderr, "mem_write failed[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
      return 1;
    }
    t_memory_page page = kh_value(memory, k);
    char *addr = (char *)page->addr;
    char *dest = &addr[start];
//    printf("mem_write address=%p, vaddr=%p, start=%ld, len=%ld, addr=%p, dest=%p\n", (void*)address, (void*)vaddr, start, len, addr, dest);
    memcpy(dest, src, len);
    src += len;
  }
  env->ReleaseByteArrayElements(bytes, data, JNI_ABORT);
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    reg_set_sp64
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_reg_1set_1sp64
  (JNIEnv *env, jclass clazz, jlong handle, jlong value) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    std::shared_ptr<Dynarmic::A64::Jit> jit = dynarmic->jit64;
    if(jit) {
      jit.get()->SetSP(value);
    } else {
      return 1;
    }
  } else {
    return -1;
  }
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    reg_set_tpidr_el0
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_reg_1set_1tpidr_1el0
  (JNIEnv *env, jclass clazz, jlong handle, jlong value) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    std::shared_ptr<DynarmicCallbacks64> cb = dynarmic->cb64;
    if(cb) {
      cb.get()->tpidr_el0 = value;
    } else {
      return 1;
    }
  } else {
    return -1;
  }
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    reg_write
 * Signature: (JIJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_reg_1write
  (JNIEnv *env, jclass clazz, jlong handle, jint index, jlong value) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    std::shared_ptr<Dynarmic::A64::Jit> jit = dynarmic->jit64;
    if(jit) {
      jit.get()->SetRegister(index, value);
    } else {
      return 1;
    }
  } else {
    return -1;
  }
  return 0;
}

#ifdef __cplusplus
}
#endif
