#include <array>
#include <cstdint>
#include <cstdio>
#include <exception>

#include <dynarmic/A32/a32.h>
#include <dynarmic/A32/config.h>

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

class MyEnvironment final : public Dynarmic::A32::UserCallbacks {
public:
    u64 ticks_left = 0;
    std::array<u8, 2048> memory{};

    u32 MemoryReadCode(u32 vaddr) override {
        u32 code = MemoryRead32(vaddr);
        printf("MemoryReadCode[%s->%s:%d]: vaddr=0x%x, code=0x%x\n", __FILE__, __func__, __LINE__, vaddr, code);
        return code;
    }

    u8 MemoryRead8(u32 vaddr) override {
        if (vaddr >= memory.size()) {
            return 0;
        }
        return memory[vaddr];
    }

    u16 MemoryRead16(u32 vaddr) override {
        return u16(MemoryRead8(vaddr)) | u16(MemoryRead8(vaddr + 1)) << 8;
    }

    u32 MemoryRead32(u32 vaddr) override {
        return u32(MemoryRead16(vaddr)) | u32(MemoryRead16(vaddr + 2)) << 16;
    }

    u64 MemoryRead64(u32 vaddr) override {
        return u64(MemoryRead32(vaddr)) | u64(MemoryRead32(vaddr + 4)) << 32;
    }

    void MemoryWrite8(u32 vaddr, u8 value) override {
        if (vaddr >= memory.size()) {
            return;
        }
        memory[vaddr] = value;
    }

    void MemoryWrite16(u32 vaddr, u16 value) override {
        MemoryWrite8(vaddr, u8(value));
        MemoryWrite8(vaddr + 1, u8(value >> 8));
    }

    void MemoryWrite32(u32 vaddr, u32 value) override {
        MemoryWrite16(vaddr, u16(value));
        MemoryWrite16(vaddr + 2, u16(value >> 16));
    }

    void MemoryWrite64(u32 vaddr, u64 value) override {
        MemoryWrite32(vaddr, u32(value));
        MemoryWrite32(vaddr + 4, u32(value >> 32));
    }

    void InterpreterFallback(u32 pc, size_t num_instructions) override {
        // This is never called in practice.
        std::terminate();
    }

    void CallSVC(u32 swi) override {
        // Do something.
    }

    void ExceptionRaised(u32 pc, Dynarmic::A32::Exception exception) override {
        printf("ExceptionRaised(exception = %lu, pc = 0x%08X, code = 0x%08X)\n", static_cast<std::size_t>(exception), pc, MemoryReadCode(pc));
    }

    void AddTicks(u64 ticks) override {
        if (ticks > ticks_left) {
            ticks_left = 0;
            return;
        }
        ticks_left -= ticks;
    }

    u64 GetTicksRemaining() override {
        return ticks_left;
    }
};

int main(int argc, char** argv) {
    MyEnvironment env;
    Dynarmic::A32::UserConfig user_config;
    user_config.callbacks = &env;
    Dynarmic::A32::Jit cpu{user_config};

    // Execute at least 1 instruction.
    // (Note: More than one instruction may be executed.)
    env.ticks_left = 1;

    // Write some code to memory.
//    env.MemoryWrite32(0, 0xe7fe2200); // mov r2, #0 : b +#0 (infinite loop)
    env.MemoryWrite32(0, 0x3f70ee1d); // mrc p15, #0, r3, c13, c0, #3
//    env.MemoryWrite32(0, 0xee1d3f70); // mrc p15, #0, r3, c13, c0, #3

    // Setup registers.
    cpu.Regs()[0] = 1;
    cpu.Regs()[1] = 2;
    cpu.Regs()[2] = 3;
    cpu.Regs()[15] = 0; // PC = 0
    cpu.SetCpsr(0x00000030); // Thumb mode

    // Execute!
    printf("Execute cpu\n");
    cpu.Run();

    // Here we would expect cpu.Regs()[0] == 8
    printf("R2: %u\n", cpu.Regs()[2]);

    return 0;
}
