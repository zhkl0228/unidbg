package net.fornwall.jelf;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import unicorn.ArmConst;

public class DwarfCursor {

    long cfa; /* canonical frame address; aka frame-/stack-pointer */
    public long ip; /* instruction pointer */

    final Long[] loc;

    protected DwarfCursor(Long[] loc) {
        this.loc = loc;
    }

    public DwarfCursor(Emulator<?> emulator) {
        this.loc = new Long[16];
        for (int i = ArmConst.UC_ARM_REG_R0; i <= ArmConst.UC_ARM_REG_R12; i++) {
            UnidbgPointer pointer = UnidbgPointer.register(emulator, i);
            loc[i-ArmConst.UC_ARM_REG_R0] = pointer == null ? 0 : pointer.peer;
        }
        UnidbgPointer r13 = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R13);
        UnidbgPointer r14 = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R14);
        UnidbgPointer r15 = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R15);
        loc[13] = r13 == null ? 0 : r13.peer;
        loc[14] = r14 == null ? 0 : r14.peer;
        loc[15] = r15 == null ? 0 : r15.peer;

        this.cfa = loc[13];
        this.ip = loc[15];
    }
}
