package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.arm.context.BackendArm32RegisterContext;
import com.github.unidbg.arm.context.BackendArm64RegisterContext;
import unicorn.ArmConst;
import unicorn.Arm64Const;

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
        RegisterContext context = emulator.getContext();
        boolean arm64 = context.getClass() == BackendArm64RegisterContext.class;
        if (arm64 || context.getClass() == BackendArm32RegisterContext.class) {
            int argument = REG_OFFSET + index;
            int count = arm64 ? 8 : 4;
            if (argument < count) {
                return context.getIntByReg((arm64 ? Arm64Const.UC_ARM64_REG_X0 : ArmConst.UC_ARM_REG_R0) + argument);
            }
            long offset = (long) (argument - count) * (arm64 ? 8 : 4);
            UnidbgPointer sp = context.getStackPointer();
            return arm64 ? (int) sp.getLong(offset) : sp.getInt(offset);
        }
        UnidbgPointer ptr = getArg(index);
        return ptr == null ? 0 : ptr.toIntPeer();
    }

}
