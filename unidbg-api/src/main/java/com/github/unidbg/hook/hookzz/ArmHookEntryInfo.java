package com.github.unidbg.hook.hookzz;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import unicorn.ArmConst;

public class ArmHookEntryInfo implements HookEntryInfo {

    private final Pointer info;

    ArmHookEntryInfo(Emulator<?> emulator) {
        info = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
    }

    @Override
    public long getHookId() {
        return info.getInt(0) & 0xffffffffL;
    }

    @Override
    public long getAddress() {
        return info.getInt(4) & 0xffffffffL;
    }
}
