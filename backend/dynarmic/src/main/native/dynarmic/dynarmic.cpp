#include <array>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <iostream>

#include <stdlib.h>
#include <unistd.h>

#if defined(_WIN32) || defined(_WIN64)
#include "mman.h"
#include <errno.h>
#else
#include <sys/mman.h>
#include <sys/errno.h>
#endif

#include "dynarmic.h"
#include "arm_dynarmic_cp15.h"

static JavaVM* cachedJVM = NULL;
static jmethodID callSVC = NULL;
static jmethodID handleInterpreterFallback = NULL;
static jmethodID handleExceptionRaised = NULL;
static jmethodID handleMemoryReadFailed = NULL;
static jmethodID handleMemoryWriteFailed = NULL;

static char *get_memory_page(khash_t(memory) *memory, u64 vaddr, size_t num_page_table_entries, void **page_table) {
    u64 idx = vaddr >> DYN_PAGE_BITS;
    if(page_table && idx < num_page_table_entries) {
      return (char *)page_table[idx];
    }
    u64 base = vaddr & ~DYN_PAGE_MASK;
    khiter_t k = kh_get(memory, memory, base);
    if(k == kh_end(memory)) {
      return NULL;
    }
    t_memory_page page = kh_value(memory, k);
    return (char *)page->addr;
}

static inline void *get_memory(khash_t(memory) *memory, u64 vaddr, size_t num_page_table_entries, void **page_table) {
    char *page = get_memory_page(memory, vaddr, num_page_table_entries, page_table);
    return page ? &page[vaddr & DYN_PAGE_MASK] : NULL;
}

class DynarmicCallbacks32 final : public Dynarmic::A32::UserCallbacks {
private:
    ~DynarmicCallbacks32() = default;

public:
    void destroy() {
        this->cp15 = nullptr;
        delete this;
    }

    DynarmicCallbacks32(khash_t(memory) *memory)
        : memory{memory}, cp15(std::make_shared<DynarmicCP15>()) {}

    bool IsReadOnlyMemory(u32 vaddr) override {
//        u32 idx;
//        return mem_map && (idx = vaddr >> DYN_PAGE_BITS) < num_page_table_entries && mem_map[idx] & PAGE_EXISTS_BIT && (mem_map[idx] & UC_PROT_WRITE) == 0;
        return false;
    }

    u16 MemoryReadThumbCode(u32 vaddr) override {
        u16 code = MemoryRead16(vaddr);
//        printf("MemoryReadThumbCode[%s->%s:%d]: vaddr=0x%x, code=0x%04x\n", __FILE__, __func__, __LINE__, vaddr, code);
        return code;
    }

    u8 MemoryRead8(u32 vaddr) override {
        u8 *dest = (u8 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
            return dest[0];
        } else {
            fprintf(stderr, "MemoryRead8[%s->%s:%d]: vaddr=0x%x\n", __FILE__, __func__, __LINE__, vaddr);
            JNIEnv *env;
            cachedJVM->AttachCurrentThread((void **)&env, NULL);
            env->CallVoidMethod(callback, handleMemoryReadFailed, vaddr, 1);
            cachedJVM->DetachCurrentThread();
            abort();
            return 0;
        }
    }
    u16 MemoryRead16(u32 vaddr) override {
        if(vaddr & 1) {
            const u8 a{MemoryRead8(vaddr)};
            const u8 b{MemoryRead8(vaddr + sizeof(u8))};
            return (static_cast<u16>(b) << 8) | a;
        }
        u16 *dest = (u16 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
            return dest[0];
        } else {
            fprintf(stderr, "MemoryRead16[%s->%s:%d]: vaddr=0x%x\n", __FILE__, __func__, __LINE__, vaddr);
            abort();
            return 0;
        }
    }
    u32 MemoryRead32(u32 vaddr) override {
        if(vaddr & 3) {
            const u16 a{MemoryRead16(vaddr)};
            const u16 b{MemoryRead16(vaddr + sizeof(u16))};
            return (static_cast<u32>(b) << 16) | a;
        }
        u32 *dest = (u32 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
//            printf("MemoryRead32[%s->%s:%d]: vaddr=0x%x, value=0x%x\n", __FILE__, __func__, __LINE__, vaddr, dest[0]);
            return dest[0];
        } else {
            printf("MemoryRead32[%s->%s:%d]: vaddr=0x%x\n", __FILE__, __func__, __LINE__, vaddr);
            JNIEnv *env;
            cachedJVM->AttachCurrentThread((void **)&env, NULL);
            env->CallVoidMethod(callback, handleMemoryReadFailed, vaddr, 4);
            cachedJVM->DetachCurrentThread();
            abort();
            return 0;
        }
    }
    u64 MemoryRead64(u32 vaddr) override {
        if(vaddr & 7) {
            const u32 a{MemoryRead32(vaddr)};
            const u32 b{MemoryRead32(vaddr + sizeof(u32))};
            return (static_cast<u64>(b) << 32) | a;
        }
        u64 *dest = (u64 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
            return dest[0];
        } else {
            fprintf(stderr, "MemoryRead64[%s->%s:%d]: vaddr=0x%x\n", __FILE__, __func__, __LINE__, vaddr);
            abort();
            return 0;
        }
    }

    void MemoryWrite8(u32 vaddr, u8 value) override {
        u8 *dest = (u8 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
            dest[0] = value;
        } else {
            fprintf(stderr, "MemoryWrite8[%s->%s:%d]: vaddr=0x%x\n", __FILE__, __func__, __LINE__, vaddr);
            JNIEnv *env;
            cachedJVM->AttachCurrentThread((void **)&env, NULL);
            env->CallVoidMethod(callback, handleMemoryWriteFailed, vaddr, 1);
            cachedJVM->DetachCurrentThread();
            abort();
        }
    }
    void MemoryWrite16(u32 vaddr, u16 value) override {
        if(vaddr & 1) {
            MemoryWrite8(vaddr, static_cast<u8>(value));
            MemoryWrite8(vaddr + sizeof(u8), static_cast<u8>(value >> 8));
            return;
        }
        u16 *dest = (u16 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
            dest[0] = value;
        } else {
            fprintf(stderr, "MemoryWrite16[%s->%s:%d]: vaddr=0x%x\n", __FILE__, __func__, __LINE__, vaddr);
            abort();
        }
    }
    void MemoryWrite32(u32 vaddr, u32 value) override {
        if(vaddr & 3) {
            MemoryWrite16(vaddr, static_cast<u16>(value));
            MemoryWrite16(vaddr + sizeof(u16), static_cast<u16>(value >> 16));
            return;
        }
        u32 *dest = (u32 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
            dest[0] = value;
        } else {
            fprintf(stderr, "MemoryWrite32[%s->%s:%d]: vaddr=0x%x\n", __FILE__, __func__, __LINE__, vaddr);
            JNIEnv *env;
            cachedJVM->AttachCurrentThread((void **)&env, NULL);
            env->CallVoidMethod(callback, handleMemoryWriteFailed, vaddr, 4);
            cachedJVM->DetachCurrentThread();
            abort();
        }
    }
    void MemoryWrite64(u32 vaddr, u64 value) override {
        if(vaddr & 7) {
            MemoryWrite32(vaddr, static_cast<u32>(value));
            MemoryWrite32(vaddr + sizeof(u32), static_cast<u32>(value >> 32));
            return;
        }
        u64 *dest = (u64 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
            dest[0] = value;
        } else {
            fprintf(stderr, "MemoryWrite64[%s->%s:%d]: vaddr=0x%x\n", __FILE__, __func__, __LINE__, vaddr);
            abort();
        }
    }

    bool MemoryWriteExclusive8(u32 vaddr, u8 value, u8 expected) override {
        fprintf(stderr, "MemoryWriteExclusive8[%s->%s:%d]: vaddr=0x%x\n", __FILE__, __func__, __LINE__, vaddr);
        abort();
        return true;
    }
    bool MemoryWriteExclusive16(u32 vaddr, u16 value, u16 expected) override {
        MemoryWrite16(vaddr, value);
        return true;
    }
    bool MemoryWriteExclusive32(u32 vaddr, u32 value, u32 expected) override {
        MemoryWrite32(vaddr, value);
        return true;
    }
    bool MemoryWriteExclusive64(u32 vaddr, u64 value, u64 expected) override {
        MemoryWrite64(vaddr, value);
        return true;
    }

    void InterpreterFallback(u32 pc, std::size_t num_instructions) override {
        fprintf(stderr, "Unicorn fallback @ 0x%x for %lu instructions (instr = 0x%08X)", pc, num_instructions, MemoryReadCode(pc));
        abort();
    }

    void ExceptionRaised(u32 pc, Dynarmic::A32::Exception exception) override {
        cpu->Regs()[15] = pc;
        printf("ExceptionRaised[%s->%s:%d]: pc=0x%x, exception=%d, code=0x%08X\n", __FILE__, __func__, __LINE__, pc, exception, MemoryReadCode(pc));
        JNIEnv *env;
        cachedJVM->AttachCurrentThread((void **)&env, NULL);
        env->CallVoidMethod(callback, handleExceptionRaised, pc, exception);
        cachedJVM->DetachCurrentThread();
        abort();
    }

    void CallSVC(u32 swi) override {
        JNIEnv *env;
        cachedJVM->AttachCurrentThread((void **)&env, NULL);
        env->CallVoidMethod(callback, callSVC, cpu->Regs()[15], swi);
        if (env->ExceptionCheck()) {
            cpu->HaltExecution();
        }
        cachedJVM->DetachCurrentThread();
    }

    void AddTicks(u64 ticks) override {
    }

    u64 GetTicksRemaining() override {
        return 0x10000000000ULL;
    }

    khash_t(memory) *memory = NULL;
    size_t num_page_table_entries;
    void **page_table = NULL;
    jobject callback = NULL;
    Dynarmic::A32::Jit *cpu;
    std::shared_ptr<DynarmicCP15> cp15;
};

class DynarmicCallbacks64 final : public Dynarmic::A64::UserCallbacks {
private:
    ~DynarmicCallbacks64() = default;

public:
    void destroy() {
        delete this;
    }

    DynarmicCallbacks64(khash_t(memory) *memory)
        : memory{memory} {}

    bool IsReadOnlyMemory(u64 vaddr) override {
//        u64 idx;
//        return mem_map && (idx = vaddr >> DYN_PAGE_BITS) < num_page_table_entries && mem_map[idx] & PAGE_EXISTS_BIT && (mem_map[idx] & UC_PROT_WRITE) == 0;
        return false;
    }

    u32 MemoryReadCode(u64 vaddr) override {
        u32 code = MemoryRead32(vaddr);
//        printf("MemoryReadCode[%s->%s:%d]: vaddr=0x%llx, code=0x%08x\n", __FILE__, __func__, __LINE__, vaddr, code);
        return code;
    }

    u8 MemoryRead8(u64 vaddr) override {
        u8 *dest = (u8 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
            return dest[0];
        } else {
            fprintf(stderr, "MemoryRead8[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
            JNIEnv *env;
            cachedJVM->AttachCurrentThread((void **)&env, NULL);
            env->CallVoidMethod(callback, handleMemoryReadFailed, vaddr, 1);
            cachedJVM->DetachCurrentThread();
            abort();
            return 0;
        }
    }
    u16 MemoryRead16(u64 vaddr) override {
        if(vaddr & 1) {
            const u8 a{MemoryRead8(vaddr)};
            const u8 b{MemoryRead8(vaddr + sizeof(u8))};
            return (static_cast<u16>(b) << 8) | a;
        }
        u16 *dest = (u16 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
            return dest[0];
        } else {
            fprintf(stderr, "MemoryRead16[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
            abort();
            return 0;
        }
    }
    u32 MemoryRead32(u64 vaddr) override {
        if(vaddr & 3) {
            const u16 a{MemoryRead16(vaddr)};
            const u16 b{MemoryRead16(vaddr + sizeof(u16))};
            return (static_cast<u32>(b) << 16) | a;
        }
        u32 *dest = (u32 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
            return dest[0];
        } else {
            fprintf(stderr, "MemoryRead32[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
            abort();
            return 0;
        }
    }
    u64 MemoryRead64(u64 vaddr) override {
        if(vaddr & 7) {
            const u32 a{MemoryRead32(vaddr)};
            const u32 b{MemoryRead32(vaddr + sizeof(u32))};
            return (static_cast<u64>(b) << 32) | a;
        }
        u64 *dest = (u64 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
            return dest[0];
        } else {
            fprintf(stderr, "MemoryRead64[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
            abort();
            return 0;
        }
    }
    Dynarmic::A64::Vector MemoryRead128(u64 vaddr) override {
        return {MemoryRead64(vaddr), MemoryRead64(vaddr + 8)};
    }

    void MemoryWrite8(u64 vaddr, u8 value) override {
        u8 *dest = (u8 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
            dest[0] = value;
        } else {
            fprintf(stderr, "MemoryWrite8[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
            abort();
        }
    }
    void MemoryWrite16(u64 vaddr, u16 value) override {
        if(vaddr & 1) {
            MemoryWrite8(vaddr, static_cast<u8>(value));
            MemoryWrite8(vaddr + sizeof(u8), static_cast<u8>(value >> 8));
            return;
        }
        u16 *dest = (u16 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
            dest[0] = value;
        } else {
            fprintf(stderr, "MemoryWrite16[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
            abort();
        }

    }
    void MemoryWrite32(u64 vaddr, u32 value) override {
        if(vaddr & 3) {
            MemoryWrite16(vaddr, static_cast<u16>(value));
            MemoryWrite16(vaddr + sizeof(u16), static_cast<u16>(value >> 16));
            return;
        }
        u32 *dest = (u32 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
            dest[0] = value;
        } else {
            fprintf(stderr, "MemoryWrite32[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
            abort();
        }
    }
    void MemoryWrite64(u64 vaddr, u64 value) override {
        if(vaddr & 7) {
            MemoryWrite32(vaddr, static_cast<u32>(value));
            MemoryWrite32(vaddr + sizeof(u32), static_cast<u32>(value >> 32));
            return;
        }
        u64 *dest = (u64 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) {
            dest[0] = value;
        } else {
            fprintf(stderr, "MemoryWrite64[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
            abort();
        }
    }
    void MemoryWrite128(u64 vaddr, Dynarmic::A64::Vector value) override {
        MemoryWrite64(vaddr, value[0]);
        MemoryWrite64(vaddr + 8, value[1]);
    }

    bool MemoryWriteExclusive8(u64 vaddr, std::uint8_t value, std::uint8_t expected) override {
        MemoryWrite8(vaddr, value);
        return true;
    }
    bool MemoryWriteExclusive16(u64 vaddr, std::uint16_t value, std::uint16_t expected) override {
        MemoryWrite16(vaddr, value);
        return true;
    }
    bool MemoryWriteExclusive32(u64 vaddr, std::uint32_t value, std::uint32_t expected) override {
        MemoryWrite32(vaddr, value);
        return true;
    }
    bool MemoryWriteExclusive64(u64 vaddr, std::uint64_t value, std::uint64_t expected) override {
        MemoryWrite64(vaddr, value);
        return true;
    }
    bool MemoryWriteExclusive128(u64 vaddr, Dynarmic::A64::Vector value, Dynarmic::A64::Vector expected) override {
        MemoryWrite128(vaddr, value);
        return true;
    }

    void InterpreterFallback(u64 pc, std::size_t num_instructions) override {
        JNIEnv *env;
        cachedJVM->AttachCurrentThread((void **)&env, NULL);
        jboolean processed = env->CallBooleanMethod(callback, handleInterpreterFallback, pc, num_instructions);
        if (env->ExceptionCheck()) {
            cpu->HaltExecution();
        }
        if(processed == JNI_TRUE) {
            cpu->SetPC(pc + 4);
        } else {
            fprintf(stderr, "Unicorn fallback @ 0x%llx for %lu instructions (instr = 0x%08X)", pc, num_instructions, MemoryReadCode(pc));
            abort();
        }
        cachedJVM->DetachCurrentThread();
    }

    void ExceptionRaised(u64 pc, Dynarmic::A64::Exception exception) override {
        switch (exception) {
            case Dynarmic::A64::Exception::Yield:
                return;
            case Dynarmic::A64::Exception::Breakpoint: // brk
            case Dynarmic::A64::Exception::WaitForInterrupt:
            case Dynarmic::A64::Exception::WaitForEvent:
            case Dynarmic::A64::Exception::SendEvent:
            case Dynarmic::A64::Exception::SendEventLocal:
            default:
                break;
        }
        cpu->SetPC(pc);
        printf("ExceptionRaised[%s->%s:%d]: pc=0x%llx, exception=%d, code=0x%08X\n", __FILE__, __func__, __LINE__, pc, exception, MemoryReadCode(pc));
        JNIEnv *env;
        cachedJVM->AttachCurrentThread((void **)&env, NULL);
        env->CallVoidMethod(callback, handleExceptionRaised, pc, exception);
        cachedJVM->DetachCurrentThread();
        abort();
    }

    void CallSVC(u32 swi) override {
        JNIEnv *env;
        cachedJVM->AttachCurrentThread((void **)&env, NULL);
        env->CallVoidMethod(callback, callSVC, cpu->GetPC(), swi);
        if (env->ExceptionCheck()) {
            cpu->HaltExecution();
        }
        cachedJVM->DetachCurrentThread();
    }

    void AddTicks(u64 ticks) override {
    }

    u64 GetTicksRemaining() override {
        return 0x10000000000ULL;
    }

    u64 GetCNTPCT() override {
        return 0x10000000000ULL;
    }

    u64 tpidrro_el0 = 0;
    u64 tpidr_el0 = 0;
    khash_t(memory) *memory = NULL;
    size_t num_page_table_entries;
    void **page_table = NULL;
    jobject callback = NULL;
    Dynarmic::A64::Jit *cpu;
};

typedef struct dynarmic {
  bool is64Bit;
  khash_t(memory) *memory;
  size_t num_page_table_entries;
  void **page_table;
  DynarmicCallbacks64 *cb64;
  Dynarmic::A64::Jit *jit64;
  DynarmicCallbacks32 *cb32;
  Dynarmic::A32::Jit *jit32;
  Dynarmic::ExclusiveMonitor *monitor;
} *t_dynarmic;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    setDynarmicCallback
 * Signature: (JLcom/github/unidbg/arm/backend/dynarmic/DynarmicCallback;)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_setDynarmicCallback
  (JNIEnv *env, jclass clazz, jlong handle, jobject callback) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    DynarmicCallbacks64 *cb = dynarmic->cb64;
    if(cb) {
      cb->callback = env->NewGlobalRef(callback);
    } else {
      return 1;
    }
  } else {
    DynarmicCallbacks32 *cb = dynarmic->cb32;
    if(cb) {
      cb->callback = env->NewGlobalRef(callback);
    } else {
      return 1;
    }
  }
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    nativeInitialize
 * Signature: (Z)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_nativeInitialize
  (JNIEnv *env, jclass clazz, jboolean is64Bit) {
  t_dynarmic dynarmic = (t_dynarmic) calloc(1, sizeof(struct dynarmic));
  if(dynarmic == NULL) {
    fprintf(stderr, "calloc dynarmic failed: size=%lu\n", sizeof(struct dynarmic));
    abort();
    return 0;
  }
  dynarmic->is64Bit = is64Bit == JNI_TRUE;
  dynarmic->memory = kh_init(memory);
  if(dynarmic->memory == NULL) {
    fprintf(stderr, "kh_init memory failed\n");
    abort();
    return 0;
  }
  int ret = kh_resize(memory, dynarmic->memory, 0x1000);
  if(ret == -1) {
    fprintf(stderr, "kh_resize memory failed\n");
    abort();
    return 0;
  }
  dynarmic->monitor = new Dynarmic::ExclusiveMonitor(1);
  if(dynarmic->is64Bit) {
    DynarmicCallbacks64 *callbacks = new DynarmicCallbacks64(dynarmic->memory);

    Dynarmic::A64::UserConfig config;
    config.callbacks = callbacks;
    config.tpidrro_el0 = &callbacks->tpidrro_el0;
    config.tpidr_el0 = &callbacks->tpidr_el0;
    config.processor_id = 0;
    config.global_monitor = dynarmic->monitor;
    config.wall_clock_cntpct = true;
//    config.page_table_pointer_mask_bits = DYN_PAGE_BITS;

//    config.unsafe_optimizations = true;
//    config.optimizations |= Dynarmic::OptimizationFlag::Unsafe_UnfuseFMA;
//    config.optimizations |= Dynarmic::OptimizationFlag::Unsafe_ReducedErrorFP;

    dynarmic->num_page_table_entries = 1ULL << (PAGE_TABLE_ADDRESS_SPACE_BITS - DYN_PAGE_BITS);
    size_t size = dynarmic->num_page_table_entries * sizeof(void*);
    dynarmic->page_table = (void **)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if(dynarmic->page_table == MAP_FAILED) {
      fprintf(stderr, "nativeInitialize mmap failed[%s->%s:%d] size=0x%zx, errno=%d, msg=%s\n", __FILE__, __func__, __LINE__, size, errno, strerror(errno));
      dynarmic->page_table = NULL;
    } else {
      callbacks->num_page_table_entries = dynarmic->num_page_table_entries;
      callbacks->page_table = dynarmic->page_table;

      // Unpredictable instructions
      config.define_unpredictable_behaviour = true;

      // Memory
      config.page_table = dynarmic->page_table;
      config.page_table_address_space_bits = PAGE_TABLE_ADDRESS_SPACE_BITS;
      config.silently_mirror_page_table = false;
      config.absolute_offset_page_table = false;
      config.detect_misaligned_access_via_page_table = 16 | 32 | 64 | 128;
      config.only_detect_misalignment_via_page_table_on_page_boundary = true;
    }

    dynarmic->cb64 = callbacks;
    dynarmic->jit64 = new Dynarmic::A64::Jit(config);
    callbacks->cpu = dynarmic->jit64;
  } else {
    DynarmicCallbacks32 *callbacks = new DynarmicCallbacks32(dynarmic->memory);

    Dynarmic::A32::UserConfig config;
    config.callbacks = callbacks;
    config.coprocessors[15] = callbacks->cp15;
    config.processor_id = 0;
    config.global_monitor = dynarmic->monitor;
    config.always_little_endian = false;
    config.wall_clock_cntpct = true;
//    config.page_table_pointer_mask_bits = DYN_PAGE_BITS;

//    config.unsafe_optimizations = true;
//    config.optimizations |= Dynarmic::OptimizationFlag::Unsafe_UnfuseFMA;
//    config.optimizations |= Dynarmic::OptimizationFlag::Unsafe_ReducedErrorFP;

    dynarmic->num_page_table_entries = Dynarmic::A32::UserConfig::NUM_PAGE_TABLE_ENTRIES;
    size_t size = dynarmic->num_page_table_entries * sizeof(void*);
    dynarmic->page_table = (void **)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if(dynarmic->page_table == MAP_FAILED) {
      fprintf(stderr, "nativeInitialize mmap failed[%s->%s:%d] size=0x%zx, errno=%d, msg=%s\n", __FILE__, __func__, __LINE__, size, errno, strerror(errno));
      dynarmic->page_table = NULL;
    } else {
      callbacks->num_page_table_entries = dynarmic->num_page_table_entries;
      callbacks->page_table = dynarmic->page_table;

      // Unpredictable instructions
      config.define_unpredictable_behaviour = true;

      // Memory
      config.page_table = reinterpret_cast<std::array<std::uint8_t*, Dynarmic::A32::UserConfig::NUM_PAGE_TABLE_ENTRIES>*>(dynarmic->page_table);
      config.absolute_offset_page_table = false;
      config.detect_misaligned_access_via_page_table = 16 | 32 | 64 | 128;
      config.only_detect_misalignment_via_page_table_on_page_boundary = true;
    }

    dynarmic->cb32 = callbacks;
    dynarmic->jit32 = new Dynarmic::A32::Jit(config);
    callbacks->cpu = dynarmic->jit32;
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
      int ret = munmap(page->addr, DYN_PAGE_SIZE);
      if(ret != 0) {
        fprintf(stderr, "munmap failed[%s->%s:%d]: addr=%p, ret=%d\n", __FILE__, __func__, __LINE__, page->addr, ret);
      }
      free(page);
    }
  }
  kh_destroy(memory, memory);
  Dynarmic::A64::Jit *jit64 = dynarmic->jit64;
  if(jit64) {
    jit64->ClearCache();
    jit64->Reset();
    delete jit64;
  }
  DynarmicCallbacks64 *cb64 = dynarmic->cb64;
  if(cb64) {
    env->DeleteGlobalRef(cb64->callback);
    cb64->destroy();
  }
  Dynarmic::A32::Jit *jit32 = dynarmic->jit32;
  if(jit32) {
    jit32->ClearCache();
    jit32->Reset();
    delete jit32;
  }
  DynarmicCallbacks32 *cb32 = dynarmic->cb32;
  if(cb32) {
    env->DeleteGlobalRef(cb32->callback);
    cb32->destroy();
  }
  if(dynarmic->page_table) {
    int ret = munmap(dynarmic->page_table, dynarmic->num_page_table_entries * sizeof(void*));
    if(ret != 0) {
      fprintf(stderr, "munmap failed[%s->%s:%d]: page_table=%p, ret=%d\n", __FILE__, __func__, __LINE__, dynarmic->page_table, ret);
    }
  }
  delete dynarmic->monitor;
  free(dynarmic);
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    mem_unmap
 * Signature: (JJJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_mem_1unmap
  (JNIEnv *env, jclass clazz, jlong handle, jlong address, jlong size) {
  if(address & DYN_PAGE_MASK) {
    return 1;
  }
  if(size == 0 || (size & DYN_PAGE_MASK)) {
    return 2;
  }
  t_dynarmic dynarmic = (t_dynarmic) handle;
  khash_t(memory) *memory = dynarmic->memory;
  int ret;
  for(u64 vaddr = address; vaddr < address + size; vaddr += DYN_PAGE_SIZE) {
    u64 idx = vaddr >> DYN_PAGE_BITS;
    khiter_t k = kh_get(memory, memory, vaddr);
    if(k == kh_end(memory)) {
      fprintf(stderr, "mem_unmap failed[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
      return 3;
    }
    if(dynarmic->page_table && idx < dynarmic->num_page_table_entries) {
      dynarmic->page_table[idx] = NULL;
    }
    t_memory_page page = kh_value(memory, k);
    int ret = munmap(page->addr, DYN_PAGE_SIZE);
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
  if(address & DYN_PAGE_MASK) {
    return 1;
  }
  if(size == 0 || (size & DYN_PAGE_MASK)) {
    return 2;
  }
  t_dynarmic dynarmic = (t_dynarmic) handle;
  khash_t(memory) *memory = dynarmic->memory;
  int ret;
  for(u64 vaddr = address; vaddr < address + size; vaddr += DYN_PAGE_SIZE) {
    u64 idx = vaddr >> DYN_PAGE_BITS;
    if(kh_get(memory, memory, vaddr) != kh_end(memory)) {
      fprintf(stderr, "mem_map failed[%s->%s:%d]: vaddr=%p\n", __FILE__, __func__, __LINE__, (void*)vaddr);
      return 3;
    }

    void *addr = mmap(NULL, DYN_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(addr == MAP_FAILED) {
      fprintf(stderr, "mmap failed[%s->%s:%d]: addr=%p\n", __FILE__, __func__, __LINE__, (void*)addr);
      return 4;
    }
    if(dynarmic->page_table && idx < dynarmic->num_page_table_entries) {
      dynarmic->page_table[idx] = addr;
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
  if(address & DYN_PAGE_MASK) {
    return 1;
  }
  if(size == 0 || (size & DYN_PAGE_MASK)) {
    return 2;
  }
  t_dynarmic dynarmic = (t_dynarmic) handle;
  khash_t(memory) *memory = dynarmic->memory;
  int ret;
  for(u64 vaddr = address; vaddr < address + size; vaddr += DYN_PAGE_SIZE) {
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
  u64 vaddr_end = address + size;
  for(u64 vaddr = address & ~DYN_PAGE_MASK; vaddr < vaddr_end; vaddr += DYN_PAGE_SIZE) {
    u64 start = vaddr < address ? address - vaddr : 0;
    u64 end = vaddr + DYN_PAGE_SIZE <= vaddr_end ? DYN_PAGE_SIZE : (vaddr_end - vaddr);
    u64 len = end - start;
    char *addr = get_memory_page(memory, vaddr, dynarmic->num_page_table_entries, dynarmic->page_table);
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
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    mem_read
 * Signature: (JJI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_mem_1read
  (JNIEnv *env, jclass clazz, jlong handle, jlong address, jint size) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  khash_t(memory) *memory = dynarmic->memory;
  jbyteArray bytes = env->NewByteArray(size);
  u64 dest = 0;
  u64 vaddr_end = address + size;
  for(u64 vaddr = address & ~DYN_PAGE_MASK; vaddr < vaddr_end; vaddr += DYN_PAGE_SIZE) {
    u64 start = vaddr < address ? address - vaddr : 0;
    u64 end = vaddr + DYN_PAGE_SIZE <= vaddr_end ? DYN_PAGE_SIZE : (vaddr_end - vaddr);
    u64 len = end - start;
    char *addr = get_memory_page(memory, vaddr, dynarmic->num_page_table_entries, dynarmic->page_table);
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
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    reg_read_pc64
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_reg_1read_1pc64
  (JNIEnv *env, jclass clazz, jlong handle) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    Dynarmic::A64::Jit *jit = dynarmic->jit64;
    if(jit) {
      return jit->GetPC();
    } else {
      abort();
      return 1;
    }
  } else {
    abort();
    return -1;
  }
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
    Dynarmic::A64::Jit *jit = dynarmic->jit64;
    if(jit) {
      jit->SetSP(value);
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
 * Method:    reg_read_sp64
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_reg_1read_1sp64
  (JNIEnv *env, jclass clazz, jlong handle) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    Dynarmic::A64::Jit *jit = dynarmic->jit64;
    if(jit) {
      return jit->GetSP();
    } else {
      abort();
      return 1;
    }
  } else {
    abort();
    return -1;
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    reg_read_nzcv
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_reg_1read_1nzcv
  (JNIEnv *env, jclass clazz, jlong handle) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    Dynarmic::A64::Jit *jit = dynarmic->jit64;
    if(jit) {
      return jit->GetPstate();
    } else {
      abort();
      return 1;
    }
  } else {
    abort();
    return -1;
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    reg_set_nzcv
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_reg_1set_1nzcv
  (JNIEnv *env, jclass clazz, jlong handle, jlong value) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    Dynarmic::A64::Jit *jit = dynarmic->jit64;
    if(jit) {
      jit->SetPstate(value);
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
    DynarmicCallbacks64 *cb = dynarmic->cb64;
    if(cb) {
      cb->tpidr_el0 = value;
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
 * Method:    reg_set_vector
 * Signature: (JI[B)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_reg_1set_1vector
  (JNIEnv *env, jclass clazz, jlong handle, jint index, jbyteArray vector) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    Dynarmic::A64::Jit *jit = dynarmic->jit64;
    if(jit) {
      jbyte *bytes = env->GetByteArrayElements(vector, NULL);
      u64 array[2];
      memcpy(array, bytes, 16);
      jit->SetVector(index, {array[0], array[1]});
      env->ReleaseByteArrayElements(vector, bytes, JNI_ABORT);
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
 * Method:    reg_set_tpidrro_el0
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_reg_1set_1tpidrro_1el0
  (JNIEnv *env, jclass clazz, jlong handle, jlong value) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    DynarmicCallbacks64 *cb = dynarmic->cb64;
    if(cb) {
      cb->tpidrro_el0 = value;
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
    Dynarmic::A64::Jit *jit = dynarmic->jit64;
    if(jit) {
      jit->SetRegister(index, value);
    } else {
      return 1;
    }
  } else {
    Dynarmic::A32::Jit *jit = dynarmic->jit32;
    if(jit) {
      jit->Regs()[index] = (u32) value;
    } else {
      return 1;
    }
  }
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    reg_read
 * Signature: (JI)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_reg_1read
  (JNIEnv *env, jclass clazz, jlong handle, jint index) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    Dynarmic::A64::Jit *jit = dynarmic->jit64;
    if(jit) {
      return jit->GetRegister(index);
    } else {
      abort();
      return -1;
    }
  } else {
    Dynarmic::A32::Jit *jit = dynarmic->jit32;
    if(jit) {
      return jit->Regs()[index];
    } else {
      abort();
      return -1;
    }
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    reg_read_cpsr
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_reg_1read_1cpsr
  (JNIEnv *env, jclass clazz, jlong handle) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    abort();
    return 1;
  } else {
    Dynarmic::A32::Jit *jit = dynarmic->jit32;
    if(jit) {
      return jit->Cpsr();
    } else {
      abort();
      return -1;
    }
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    reg_write_cpsr
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_reg_1write_1cpsr
  (JNIEnv *env, jclass clazz, jlong handle, jint value) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    abort();
    return 1;
  } else {
    Dynarmic::A32::Jit *jit = dynarmic->jit32;
    if(jit) {
      jit->SetCpsr(value);
      return 0;
    } else {
      abort();
      return -1;
    }
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    reg_write_c13_c0_3
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_reg_1write_1c13_1c0_13
  (JNIEnv *env, jclass clazz, jlong handle, jint value) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    abort();
    return 1;
  } else {
    DynarmicCallbacks32 *cb32 = dynarmic->cb32;
    if(cb32) {
      cb32->cp15.get()->uro = value;
      return 0;
    } else {
      abort();
      return -1;
    }
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    emu_start
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_emu_1start
  (JNIEnv *env, jclass clazz, jlong handle, jlong pc) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    Dynarmic::A64::Jit *jit = dynarmic->jit64;
    if(jit) {
      Dynarmic::A64::Jit *cpu = jit;
      cpu->SetPC(pc);
      cpu->Run();
    } else {
      return 1;
    }
  } else {
    Dynarmic::A32::Jit *jit = dynarmic->jit32;
    if(jit) {
      Dynarmic::A32::Jit *cpu = jit;
      bool thumb = pc & 1;
      if(pc & 1) {
        cpu->SetCpsr(0x00000030); // Thumb user mode
      } else {
        cpu->SetCpsr(0x000001d0); // Arm user mode
      }
      cpu->Regs()[15] = (u32) (pc & ~1);
      cpu->Run();
    } else {
      return 1;
    }
  }
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    emu_stop
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_emu_1stop
  (JNIEnv *env, jclass clazz, jlong handle) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  if(dynarmic->is64Bit) {
    Dynarmic::A64::Jit *jit = dynarmic->jit64;
    if(jit) {
      Dynarmic::A64::Jit *cpu = jit;
      cpu->HaltExecution();
    } else {
      return 1;
    }
  } else {
    Dynarmic::A32::Jit *jit = dynarmic->jit32;
    if(jit) {
      Dynarmic::A32::Jit *cpu = jit;
      cpu->HaltExecution();
    } else {
      return 1;
    }
  }
  return 0;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  JNIEnv *env;
  if (JNI_OK != vm->GetEnv((void **)&env, JNI_VERSION_1_6)) {
    return JNI_ERR;
  }
  jclass cDynarmicCallback = env->FindClass("com/github/unidbg/arm/backend/dynarmic/DynarmicCallback");
  if (env->ExceptionCheck()) {
    return JNI_ERR;
  }
  callSVC = env->GetMethodID(cDynarmicCallback, "callSVC", "(JI)V");
  handleInterpreterFallback = env->GetMethodID(cDynarmicCallback, "handleInterpreterFallback", "(JI)Z");
  handleExceptionRaised = env->GetMethodID(cDynarmicCallback, "handleExceptionRaised", "(JI)V");
  handleMemoryReadFailed = env->GetMethodID(cDynarmicCallback, "handleMemoryReadFailed", "(JI)V");
  handleMemoryWriteFailed = env->GetMethodID(cDynarmicCallback, "handleMemoryWriteFailed", "(JI)V");
  cachedJVM = vm;

  return JNI_VERSION_1_6;
}

#ifdef __cplusplus
}
#endif
