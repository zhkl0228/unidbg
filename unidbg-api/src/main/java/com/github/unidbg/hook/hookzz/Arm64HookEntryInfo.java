package com.github.unidbg.hook.hookzz;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import unicorn.Arm64Const;

public class Arm64HookEntryInfo implements HookEntryInfo {

    private final Pointer info;

    Arm64HookEntryInfo(Emulator<?> emulator) {
        info = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
    }

    @Override
    public long getHookId() {
        return info.getLong(0);
    }

    @Override
    public long getAddress() {
        return info.getLong(8);
    }
}
