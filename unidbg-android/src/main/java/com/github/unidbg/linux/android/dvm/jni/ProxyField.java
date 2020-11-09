package com.github.unidbg.linux.android.dvm.jni;

import java.lang.reflect.Field;

class ProxyField {

    private final Field field;

    ProxyField(Field field) {
        this.field = field;
    }

    final Object get(Object thisObj) throws IllegalAccessException {
        return field.get(thisObj);
    }

    final long getLong(Object thisObj) throws IllegalAccessException {
        return field.getLong(thisObj);
    }

    final boolean getBoolean(Object thisObj) throws IllegalAccessException {
        return field.getBoolean(thisObj);
    }

    final int getInt(Object thisObj) throws IllegalAccessException {
        return field.getInt(thisObj);
    }

    final void setInt(Object thisObj, int value) throws IllegalAccessException {
        field.setInt(thisObj, value);
    }

    final void setDouble(Object thisObj, double value) throws IllegalAccessException {
        field.setDouble(thisObj, value);
    }

    final void setObject(Object thisObj, Object value) throws IllegalAccessException {
        field.set(thisObj, value);
    }

    final void setBoolean(Object thisObj, boolean value) throws IllegalAccessException {
        field.setBoolean(thisObj, value);
    }

    final void setLong(Object thisObj, long value) throws IllegalAccessException {
        field.setLong(thisObj, value);
    }

}
