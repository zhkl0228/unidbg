package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.memory.MemoryBlock;

public class StringObject extends DvmObject<String> {

    public StringObject(VM vm, String value) {
        super(vm.resolveClass("java/lang/String"), value);

        if (value == null) {
            throw new NullPointerException();
        }
    }

    MemoryBlock memoryBlock;

    @Override
    public String toString() {
        if (value == null) {
            return null;
        } else {
            return '"' + value + '"';
        }
    }
}
