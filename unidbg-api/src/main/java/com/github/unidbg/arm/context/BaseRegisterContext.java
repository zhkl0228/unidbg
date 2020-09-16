package com.github.unidbg.arm.context;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnicornPointer;
import unicorn.Unicorn;

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
    public UnicornPointer getPointerArg(int index) {
        if (index < regArgCount) {
            int reg = firstArgReg + index;
            return UnicornPointer.register(emulator, reg);
        }

        UnicornPointer sp = getStackPointer();
        return sp.getPointer((index - regArgCount) * emulator.getPointerSize());
    }

    @Override
    public int getInt(int regId) {
        Unicorn unicorn = emulator.getUnicorn();
        Number number = (Number) unicorn.reg_read(regId);
        return number.intValue();
    }

    @Override
    public long getLong(int regId) {
        Unicorn unicorn = emulator.getUnicorn();
        Number number = (Number) unicorn.reg_read(regId);
        return number.longValue();
    }

}
