package com.github.unidbg.linux.android.dvm.wrapper;

import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

public class DvmInteger extends DvmObject<Integer> {

    @SuppressWarnings("unused")
    public static DvmInteger valueOf(VM vm, int i) {
        return new DvmInteger(vm, i);
    }

    private DvmInteger(VM vm, Integer value) {
        super(vm.resolveClass("java/lang/Integer"), value);
    }

    @Override
    public String toString() {
        return "0x" + Integer.toHexString(value);
    }
}
