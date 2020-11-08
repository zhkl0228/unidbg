package com.github.unidbg.linux.android.dvm.jni;

import java.lang.reflect.Field;

class ProxyField {

    private final Field field;

    ProxyField(Field field) {
        this.field = field;
    }

    final Object get(Object thisObj) throws IllegalAccessException {
        field.setAccessible(true);
        return field.get(thisObj);
    }

    final long getLong(Object thisObj) throws IllegalAccessException {
        field.setAccessible(true);
        return field.getLong(thisObj);
    }

    final boolean getBoolean(Object thisObj) throws IllegalAccessException {
        field.setAccessible(true);
        return field.getBoolean(thisObj);
    }

    final void setInt(Object thisObj, int value) throws IllegalAccessException {
        field.setAccessible(true);
        field.setInt(thisObj, value);
    }

}
