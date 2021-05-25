package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;

public abstract class ArmVarArg extends VarArg {

    static VarArg create(Emulator<?> emulator, BaseVM vm, DvmMethod method) {
        return emulator.is64Bit() ? new ArmVarArg64(emulator, vm, method) : new ArmVarArg32(emulator, vm, method);
    }

    protected final Emulator<?> emulator;

    protected ArmVarArg(Emulator<?> emulator, BaseVM vm, DvmMethod method) {
        super(vm, method);
        this.emulator = emulator;
    }

    private static final int REG_OFFSET = 3;

    protected final UnidbgPointer getArg(int index) {
        return emulator.getContext().getPointerArg(REG_OFFSET + index);
    }

    protected final int getInt(int index) {
        UnidbgPointer ptr = getArg(index);
        return ptr == null ? 0 : ptr.toIntPeer();
    }

}
