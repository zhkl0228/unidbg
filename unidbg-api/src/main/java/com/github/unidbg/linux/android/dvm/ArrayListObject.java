package com.github.unidbg.linux.android.dvm;

import java.util.List;

public class ArrayListObject extends DvmObject<List<? extends DvmObject<?>>> {

    public ArrayListObject(VM vm, List<? extends DvmObject<?>> value) {
        super(vm.resolveClass("java/util/ArrayList"), value);
    }

    public int size() {
        return value.size();
    }

    public boolean isEmpty() {
        return value.isEmpty();
    }

}
