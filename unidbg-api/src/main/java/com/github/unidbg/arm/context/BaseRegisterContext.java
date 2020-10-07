package com.github.unidbg.arm.context;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.pointer.UnidbgPointer;

public abstract class BaseRegisterContext extends AbstractRegisterContext implements RegisterContext {

    protected final Emulator<?> emulator;
    private final int firstArgReg;
    private final int regArgCount;

    BaseRegisterContext(Emulator<?> emulator, int firstArgReg, int regArgCount) {
        this.emulator = emulator;
        this.firstArgReg = firstArgReg;
        this.regArgCount = regArgCount;
    }

    @Override
    public UnidbgPointer getPointerArg(int index) {
        if (index < regArgCount) {
            int reg = firstArgReg + index;
            return UnidbgPointer.register(emulator, reg);
        }

        UnidbgPointer sp = getStackPointer();
        return sp.getPointer((index - regArgCount) * emulator.getPointerSize());
    }

    @Override
    public int getInt(int regId) {
        Backend backend = emulator.getBackend();
        Number number = backend.reg_read(regId);
        return number.intValue();
    }

    @Override
    public long getLong(int regId) {
        Backend backend = emulator.getBackend();
        Number number = backend.reg_read(regId);
        return number.longValue();
    }

}
