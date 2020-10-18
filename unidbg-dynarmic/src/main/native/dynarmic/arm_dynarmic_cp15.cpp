// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <fmt/format.h>
#include "arm_dynarmic_cp15.h"

using Callback = Dynarmic::A32::Coprocessor::Callback;
using CallbackOrAccessOneWord = Dynarmic::A32::Coprocessor::CallbackOrAccessOneWord;
using CallbackOrAccessTwoWords = Dynarmic::A32::Coprocessor::CallbackOrAccessTwoWords;

template <>
struct fmt::formatter<Dynarmic::A32::CoprocReg> {
    constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }
    template <typename FormatContext>
    auto format(const Dynarmic::A32::CoprocReg& reg, FormatContext& ctx) {
        return format_to(ctx.out(), "cp{}", static_cast<size_t>(reg));
    }
};

static u32 dummy_value;

std::optional<Callback> DynarmicCP15::CompileInternalOperation(bool two, unsigned opc1,
                                                               CoprocReg CRd, CoprocReg CRn,
                                                               CoprocReg CRm, unsigned opc2) {
    printf("CompileInternalOperation two=%d, opc1=%u, CRd=%d, CRn=%d, CRm=%d, opc2=%u\n", two, opc1, CRd, CRn, CRm, opc2);
    return std::nullopt;
}

CallbackOrAccessOneWord DynarmicCP15::CompileSendOneWord(bool two, unsigned opc1, CoprocReg CRn,
                                                         CoprocReg CRm, unsigned opc2) {
    printf("CompileSendOneWord two=%d, opc1=%u, CRn=%d, CRm=%d, opc2=%u\n", two, opc1, CRn, CRm, opc2);
    if (!two && CRn == CoprocReg::C7 && opc1 == 0 && CRm == CoprocReg::C5 && opc2 == 4) {
        // CP15_FLUSH_PREFETCH_BUFFER
        // This is a dummy write, we ignore the value written here.
        return &dummy_value;
    }

    if (!two && CRn == CoprocReg::C7 && opc1 == 0 && CRm == CoprocReg::C10) {
        switch (opc2) {
        case 4:
            // CP15_DATA_SYNC_BARRIER
            // This is a dummy write, we ignore the value written here.
            return &dummy_value;
        case 5:
            // CP15_DATA_MEMORY_BARRIER
            // This is a dummy write, we ignore the value written here.
            return &dummy_value;
        }
    }

    if (!two && CRn == CoprocReg::C13 && opc1 == 0 && CRm == CoprocReg::C0 && opc2 == 2) {
        // CP15_THREAD_UPRW
        return &uprw;
    }

    return {};
}

CallbackOrAccessTwoWords DynarmicCP15::CompileSendTwoWords(bool two, unsigned opc, CoprocReg CRm) {
    printf("CompileSendTwoWords two=%d, opc=%u, CRm=%d\n", two, opc, CRm);
    return {};
}

CallbackOrAccessOneWord DynarmicCP15::CompileGetOneWord(bool two, unsigned opc1, CoprocReg CRn,
                                                        CoprocReg CRm, unsigned opc2) {
    if (!two && CRn == CoprocReg::C13 && opc1 == 0 && CRm == CoprocReg::C0) {
        switch (opc2) {
        case 2:
            // CP15_THREAD_UPRW
            return &uprw;
        case 3:
            // CP15_THREAD_URO
            return &uro;
        }
    }

    return {};
}

CallbackOrAccessTwoWords DynarmicCP15::CompileGetTwoWords(bool two, unsigned opc, CoprocReg CRm) {
    printf("CompileGetTwoWords two=%d, opc=%u, CRm=%d\n", two, opc, CRm);
    if (!two && opc == 0 && CRm == CoprocReg::C14) {
        // CNTPCT
        const auto callback = static_cast<u64 (*)(Dynarmic::A32::Jit*, void*, u32, u32)>(
            [](Dynarmic::A32::Jit*, void* arg, u32, u32) -> u64 {
                return 0x10000000000;
            });
        return Dynarmic::A32::Coprocessor::Callback{callback, nullptr};
    }

    return {};
}

std::optional<Callback> DynarmicCP15::CompileLoadWords(bool two, bool long_transfer, CoprocReg CRd,
                                                       std::optional<u8> option) {
    printf("CompileLoadWords two=%d, CRd=%d\n", two, CRd);
    return std::nullopt;
}

std::optional<Callback> DynarmicCP15::CompileStoreWords(bool two, bool long_transfer, CoprocReg CRd,
                                                        std::optional<u8> option) {
    printf("CompileStoreWords two=%d, CRd=%d\n", two, CRd);
    return std::nullopt;
}
