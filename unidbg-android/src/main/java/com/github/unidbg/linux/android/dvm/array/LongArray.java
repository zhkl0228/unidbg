package com.github.unidbg.linux.android.dvm.array;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

public class LongArray extends BaseArray<long[]> implements PrimitiveArray<long[]> {

    public LongArray(VM vm, long[] value) {
        super(vm.resolveClass("[J"), value);
    }

    @Override
    public int length() {
        return value.length;
    }

    public void setValue(long[] value) {
        super.value = value;
    }

    @Override
    public void setData(int start, long[] data) {
        System.arraycopy(data, 0, value, start, data.length);
    }

    @Override
    public UnidbgPointer _GetArrayCritical(Emulator<?> emulator, Pointer isCopy) {
        if (isCopy != null) {
            isCopy.setInt(0, VM.JNI_TRUE);
        }
        UnidbgPointer pointer = this.allocateMemoryBlock(emulator, value.length * 8);
        pointer.write(0, value, 0, value.length);
        return pointer;
    }

    @Override
    public void _ReleaseArrayCritical(Pointer elems, int mode) {
        switch (mode) {
            case VM.JNI_COMMIT:
                this.readFromPointer(elems);
                break;
            case 0:
                this.readFromPointer(elems);
            case VM.JNI_ABORT:
                this.freeMemoryBlock(elems);
                break;
        }
    }

    private void readFromPointer(Pointer elems) {
        this.setValue(elems.getLongArray(0, this.value.length));
    }
}
