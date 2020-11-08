package com.github.unidbg.linux.android.dvm.jni;

import java.lang.reflect.Field;

class ProxyField {

    private final Field field;

    ProxyField(Field field) {
        this.field = field;
    }

    public Object get(Object thisObj) throws IllegalAccessException {
        field.setAccessible(true);
        return field.get(thisObj);
    }

}
