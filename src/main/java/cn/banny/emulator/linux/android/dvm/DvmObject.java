package cn.banny.emulator.linux.android.dvm;

import unicorn.UnicornException;

public class DvmObject<T> implements Hashable {

    final DvmClass objectType;
    protected T value;

    public DvmObject(DvmClass objectType, T value) {
        this.objectType = objectType;
        this.value = value;
    }

    public T getValue() {
        return value;
    }

    public DvmClass getObjectType() {
        return objectType;
    }

    protected boolean isInstanceOf(VM vm, DvmClass dvmClass) {
        throw new UnicornException();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "{" +
                "value=" + value +
                '}';
    }
}
