package net.fornwall.jelf;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnicornPointer;
import unicorn.Arm64Const;

public class DwarfCursor64 extends DwarfCursor {

    public DwarfCursor64(Emulator<?> emulator) {
        super(new Long[100]);

        for (int i = Arm64Const.UC_ARM64_REG_X0; i <= Arm64Const.UC_ARM64_REG_X28; i++) {
            UnicornPointer pointer = UnicornPointer.register(emulator, i);
            loc[i-Arm64Const.UC_ARM64_REG_X0] = pointer == null ? 0 : pointer.peer;
        }
        UnicornPointer x29 = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_FP);
        UnicornPointer x30 = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR);
        UnicornPointer x31 = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_SP);
        loc[29] = x29 == null ? 0 : x29.peer;
        loc[30] = x30 == null ? 0 : x30.peer;
        loc[31] = x31 == null ? 0 : x31.peer;

        this.cfa = loc[31];
        this.ip = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_PC).peer;
    }
}
