package com.github.unidbg.linux.android.dvm.array;

import com.github.unidbg.linux.android.dvm.Array;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;

abstract class BaseArray<T> extends DvmObject<T> implements Array<T> {

    BaseArray(DvmClass objectType, T value) {
        super(objectType, value);
    }

    @Override
    public String toString() {
        return String.valueOf(value);
    }

}
