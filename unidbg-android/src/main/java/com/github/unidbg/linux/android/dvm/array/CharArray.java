package com.github.unidbg.linux.android.dvm.array;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

public class CharArray extends BaseArray<char[]> implements PrimitiveArray<char[]> {

    public CharArray(VM vm, char[] value) {
        super(vm.resolveClass("[C"), value);
    }

    @Override
    public int length() {
        return value.length;
    }

    public void setValue(char[] value) {
        super.value = value;
    }

    @Override
    public void setData(int start, char[] data) {
        System.arraycopy(data, 0, value, start, data.length);
    }

    @Override
    public UnidbgPointer _GetArrayCritical(Emulator<?> emulator, Pointer isCopy) {
        if (isCopy != null) {
            isCopy.setInt(0, VM.JNI_TRUE);
        }
        UnidbgPointer pointer = this.allocateMemoryBlock(emulator, value.length * 2);
        for (int i = 0; i < value.length; i++) {
            pointer.setShort(i * 2, (short) value[i]);
        }
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
        for (int i = 0; i < value.length; i++) {
            value[i] = (char) elems.getShort(i * 2);
        }
    }

    @Override
    public String toString() {
        if (value != null && value.length <= 64) {
            return "[C@" + new String(value);
        } else {
            return super.toString();
        }
    }
}
