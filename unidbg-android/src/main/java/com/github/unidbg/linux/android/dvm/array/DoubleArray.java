package com.github.unidbg.linux.android.dvm.array;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

public class DoubleArray extends BaseArray<double[]> implements PrimitiveArray<double[]> {

    public DoubleArray(VM vm, double[] value) {
        super(vm.resolveClass("[D"), value);
    }

    @Override
    public int length() {
        return value.length;
    }

    @Override
    public void setData(int start, double[] data) {
        System.arraycopy(data, 0, value, start, data.length);
    }

    @Override
    public UnidbgPointer _GetArrayCritical(Emulator<?> emulator, Pointer isCopy) {
        throw new BackendException();
    }

    @Override
    public void _ReleaseArrayCritical(Pointer elems, int mode) {
        throw new BackendException();
    }
}
