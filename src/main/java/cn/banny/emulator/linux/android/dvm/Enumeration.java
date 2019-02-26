package cn.banny.emulator.linux.android.dvm;

import java.util.Iterator;
import java.util.List;

public class Enumeration extends DvmObject<List<?>> {

    private Iterator<? extends DvmObject> iterator;

    public Enumeration(DvmClass objectType, List<? extends DvmObject> value) {
        super(objectType, value);

        this.iterator = value == null ? null : value.iterator();
    }

    public boolean hasMoreElements() {
        return iterator != null && iterator.hasNext();
    }

    public DvmObject nextElement() {
        return iterator.next();
    }

}
