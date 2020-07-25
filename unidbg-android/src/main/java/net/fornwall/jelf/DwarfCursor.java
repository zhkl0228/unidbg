package net.fornwall.jelf;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnicornPointer;
import unicorn.ArmConst;

public class DwarfCursor {

    long cfa; /* canonical frame address; aka frame-/stack-pointer */
    public long ip; /* instruction pointer */

    final Long[] loc;

    public DwarfCursor(Emulator<?> emulator) {
        this.loc = new Long[16];
        for (int i = ArmConst.UC_ARM_REG_R0; i <= ArmConst.UC_ARM_REG_R12; i++) {
            UnicornPointer pointer = UnicornPointer.register(emulator, i);
            loc[i-ArmConst.UC_ARM_REG_R0] = pointer == null ? 0 : pointer.peer;
        }
        UnicornPointer r13 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R13);
        UnicornPointer r14 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R14);
        UnicornPointer r15 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R15);
        loc[13] = r13 == null ? 0 : r13.peer;
        loc[14] = r14 == null ? 0 : r14.peer;
        loc[15] = r15 == null ? 0 : r15.peer;

        this.cfa = loc[13];
        this.ip = loc[15];
    }
}
