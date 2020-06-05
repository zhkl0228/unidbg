package com.github.unidbg.linux.android.dvm.array;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import unicorn.UnicornException;

public class DoubleArray extends BaseArray<double[]> implements PrimitiveArray<double[]> {

    public DoubleArray(double[] value) {
        super(value);
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
    public UnicornPointer _GetArrayCritical(Emulator<?> emulator, Pointer isCopy) {
        throw new UnicornException();
    }

    @Override
    public void _ReleaseArrayCritical(Pointer elems, int mode) {
        throw new UnicornException();
    }
}
