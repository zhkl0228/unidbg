package com.github.unidbg.linux.android.dvm.jni;

import unicorn.UnicornException;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

class ProxyMethod implements ProxyCall {

    private final Method method;
    private final Object[] args;

    ProxyMethod(Method method, Object[] args) {
        this.method = method;
        this.args = args;
    }

    @Override
    public Object call(Object obj) throws IllegalAccessException, InvocationTargetException {
        try {
            return method.invoke(obj, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getTargetException();
            if (cause instanceof UnicornException) {
                throw (UnicornException) cause;
            }
            throw e;
        }
    }
}
