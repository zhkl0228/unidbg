package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.arm.context.BackendArm64RegisterContext;
import unicorn.Arm64Const;

class ArmVarArg64 extends ArmVarArg {

    ArmVarArg64(Emulator<?> emulator, BaseVM vm, DvmMethod method) {
        super(emulator, vm, method);

        int offset = 0;
        int floatOff = 0;
        for (Shorty shorty : shorties) {
            switch (shorty.getType()) {
                case 'L':
                case 'B':
                case 'C':
                case 'I':
                case 'S':
                case 'Z': {
                    args.add(getInt(offset++));
                    break;
                }
                case 'D': {
                    args.add(getVectorArg(floatOff++));
                    break;
                }
                case 'F': {
                    args.add((float) getVectorArg(floatOff++));
                    break;
                }
                case 'J': {
                    args.add(getLongValue64(offset++));
                    break;
                }
                default:
                    throw new IllegalStateException("c=" + shorty.getType());
            }
        }
    }

    private long getLongValue64(int index) {
        RegisterContext context = emulator.getContext();
        if (context.getClass() == BackendArm64RegisterContext.class) {
            int argument = 3 + index;
            if (argument < 8) {
                return context.getLongByReg(Arm64Const.UC_ARM64_REG_X0 + argument);
            }
            return context.getStackPointer().getLong((long) (argument - 8) * 8);
        }
        UnidbgPointer ptr = getArg(index);
        return ptr == null ? 0L : ptr.peer;
    }

    private double getVectorArg(int index) {
        byte[] vector = emulator.getBackend().reg_read_vector(Arm64Const.UC_ARM64_REG_Q0 + index);
        if (vector.length > 16) {
            throw new java.nio.BufferOverflowException();
        }
        if (vector.length < 8) {
            throw new java.nio.BufferUnderflowException();
        }
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value |= (vector[i] & 0xffL) << (i * 8);
        }
        return Double.longBitsToDouble(value);
    }
}
