package com.github.unidbg.linux.android.dvm;

import java.util.Iterator;
import java.util.List;

public class Enumeration extends DvmObject<List<?>> {

    private final Iterator<? extends DvmObject<?>> iterator;

    public Enumeration(VM vm, List<? extends DvmObject<?>> value) {
        super(vm.resolveClass("java/util/Enumeration"), value);

        this.iterator = value == null ? null : value.iterator();
    }

    public boolean hasMoreElements() {
        return iterator != null && iterator.hasNext();
    }

    public DvmObject<?> nextElement() {
        return iterator.next();
    }

}
