package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class ArmVarArg implements VarArg {

    static VarArg create(Emulator<?> emulator, BaseVM vm) {
        return new ArmVarArg(emulator, vm);
    }

    private final Emulator<?> emulator;
    private final BaseVM vm;

    private ArmVarArg(Emulator<?> emulator, BaseVM vm) {
        this.emulator = emulator;
        this.vm = vm;
    }

    @Override
    public <T extends DvmObject<?>> T getObject(int index) {
        UnidbgPointer pointer = getArg(index);
        if (pointer == null) {
            return null;
        } else {
            return vm.getObject(pointer.toIntPeer());
        }
    }

    @Override
    public int getInt(int index) {
        UnidbgPointer pointer = getArg(index);
        return pointer == null ? 0 : (int) pointer.peer;
    }

    @Override
    public double getDouble(int index) {
        if (emulator.is64Bit()) {
            throw new UnsupportedOperationException();
        }

        int v1 = getInt(index);
        int v2 = getInt(index + 1);
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(v1);
        buffer.putInt(v2);
        buffer.flip();
        return buffer.getDouble();
    }

    private static final int REG_OFFSET = 3;

    private UnidbgPointer getArg(int index) {
        return emulator.getContext().getPointerArg(REG_OFFSET + index);
    }

}
