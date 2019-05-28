package cn.banny.unidbg.arm.context;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.pointer.UnicornPointer;

public abstract class BaseRegisterContext extends AbstractRegisterContext implements RegisterContext {

    protected final Emulator emulator;
    private final int firstArgReg;
    private final int regArgCount;

    BaseRegisterContext(Emulator emulator, int firstArgReg, int regArgCount) {
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

}
