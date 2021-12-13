package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.memory.Memory;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class EntryTask extends MainTask {

    private final long sp;

    public EntryTask(long begin, long until, long sp) {
        super(begin, until);
        this.sp = sp;
    }

    @Override
    protected Number run(AbstractEmulator<?> emulator) {
        Backend backend = emulator.getBackend();
        Memory memory = emulator.getMemory();
        memory.setStackPoint(sp);
        backend.reg_write(emulator.is64Bit() ? Arm64Const.UC_ARM64_REG_LR : ArmConst.UC_ARM_REG_LR, until);
        return emulator.emulate(begin, until);
    }

}
