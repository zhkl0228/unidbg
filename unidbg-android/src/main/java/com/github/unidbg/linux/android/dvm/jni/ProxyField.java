package com.github.unidbg.linux.android.dvm.jni;

import java.lang.reflect.Field;

class ProxyField {

    private final ProxyDvmObjectVisitor visitor;
    private final Field field;

    ProxyField(ProxyDvmObjectVisitor visitor, Field field) {
        this.visitor = visitor;
        this.field = field;
    }

    final Object get(Object thisObj) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, null);
        }
        return field.get(thisObj);
    }

    final long getLong(Object thisObj) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, null);
        }
        return field.getLong(thisObj);
    }

    final float getFloat(Object thisObj) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, null);
        }
        return field.getFloat(thisObj);
    }

    final boolean getBoolean(Object thisObj) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, null);
        }
        return field.getBoolean(thisObj);
    }

    final int getInt(Object thisObj) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, null);
        }
        return field.getInt(thisObj);
    }

    final void setInt(Object thisObj, int value) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, new Object[] { value });
        }
        field.setInt(thisObj, value);
    }

    final void setDouble(Object thisObj, double value) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, new Object[] { value });
        }
        field.setDouble(thisObj, value);
    }

    final void setObject(Object thisObj, Object value) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, new Object[] { value });
        }
        field.set(thisObj, value);
    }

    final void setBoolean(Object thisObj, boolean value) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, new Object[] { value });
        }
        field.setBoolean(thisObj, value);
    }

    final void setLong(Object thisObj, long value) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, new Object[] { value });
        }
        field.setLong(thisObj, value);
    }

}
