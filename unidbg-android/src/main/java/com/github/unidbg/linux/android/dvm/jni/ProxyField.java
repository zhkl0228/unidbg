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
        Object result = field.get(thisObj);
        if (visitor != null) {
            result = visitor.postProxyVisit(field, thisObj, null, result);
        }
        return result;
    }

    final long getLong(Object thisObj) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, null);
        }
        long result = field.getLong(thisObj);
        if (visitor != null) {
            result = visitor.postProxyVisit(field, thisObj, null, result);
        }
        return result;
    }

    final float getFloat(Object thisObj) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, null);
        }
        float result = field.getFloat(thisObj);
        if (visitor != null) {
            result = visitor.postProxyVisit(field, thisObj, null, result);
        }
        return result;
    }

    final boolean getBoolean(Object thisObj) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, null);
        }
        boolean result = field.getBoolean(thisObj);
        if (visitor != null) {
            result = visitor.postProxyVisit(field, thisObj, null, result);
        }
        return result;
    }

    final byte getByte(Object thisObj) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, null);
        }
        byte result = field.getByte(thisObj);
        if (visitor != null) {
            result = visitor.postProxyVisit(field, thisObj, null, result);
        }
        return result;
    }

    final int getInt(Object thisObj) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, null);
        }
        int result = field.getInt(thisObj);
        if (visitor != null) {
            result = visitor.postProxyVisit(field, thisObj, null, result);
        }
        return result;
    }

    final void setInt(Object thisObj, int value) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, new Object[] { value });
        }
        field.setInt(thisObj, value);
    }

    final void setFloat(Object thisObj, float value) throws IllegalAccessException {
        if (visitor != null) {
            visitor.onProxyVisit(field, thisObj, new Object[] { value });
        }
        field.setFloat(thisObj, value);
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
