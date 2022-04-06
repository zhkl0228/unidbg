package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.memory.Memory;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class Entry extends MainTask {

    private final long entry;
    private final long sp;

    public Entry(int pid, long entry, long until, long sp) {
        super(pid, until);
        this.entry = entry;
        this.sp = sp;
    }

    @Override
    protected Number run(AbstractEmulator<?> emulator) {
        Backend backend = emulator.getBackend();
        Memory memory = emulator.getMemory();
        memory.setStackPoint(sp);
        backend.reg_write(emulator.is64Bit() ? Arm64Const.UC_ARM64_REG_LR : ArmConst.UC_ARM_REG_LR, until);
        return emulator.emulate(entry, until);
    }

    @Override
    public String toString() {
        return "Executable entry=0x" + Long.toHexString(entry) + ", sp=0x" + Long.toHexString(sp);
    }
}
