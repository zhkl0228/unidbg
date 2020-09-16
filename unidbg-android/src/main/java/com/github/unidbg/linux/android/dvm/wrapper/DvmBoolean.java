package com.github.unidbg.linux.android.dvm.wrapper;

import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

public class DvmBoolean extends DvmObject<Boolean> {

    @SuppressWarnings("unused")
    public static DvmBoolean valueOf(VM vm, boolean b) {
        return new DvmBoolean(vm, b);
    }

    private DvmBoolean(VM vm, Boolean value) {
        super(vm.resolveClass("java/lang/Boolean"), value);
    }

    @Override
    public String toString() {
        return Boolean.toString(value);
    }
}
