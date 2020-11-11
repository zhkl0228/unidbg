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
            patch(obj, args);

            return method.invoke(obj, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getTargetException();
            if (cause instanceof UnicornException) {
                throw (UnicornException) cause;
            }
            throw e;
        }
    }

    private void patch(Object obj, Object[] args) {
        if (obj instanceof ClassLoader &&
                "loadClass".equals(method.getName()) &&
                args.length == 1) {
            String binaryName = (String) args[0];
            args[0] = binaryName.replace('/', '.');
        }
    }
}
