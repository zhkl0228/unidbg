package com.github.unidbg.linux.android.dvm;

import java.util.ArrayList;
import java.util.List;

public class ArrayListObject extends DvmObject<List<? extends DvmObject<?>>> {

    @SuppressWarnings("unused")
    public static ArrayListObject newStringList(VM vm, String... strings) {
        List<StringObject> list = new ArrayList<>();
        for (String str : strings) {
            if (str != null) {
                list.add(new StringObject(vm, str));
            }
        }
        return new ArrayListObject(vm, list);
    }

    public ArrayListObject(VM vm, List<? extends DvmObject<?>> value) {
        super(vm.resolveClass("java/util/ArrayList", vm.resolveClass("java/util/List")), value);
    }

    public int size() {
        return value.size();
    }

    public boolean isEmpty() {
        return value.isEmpty();
    }

}
