package com.github.unidbg.linux.android.dvm.jni;

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
    public Object call(Object obj) throws IllegalAccessException, InvocationTargetException, InstantiationException {
        method.setAccessible(true);
        return method.invoke(obj, args);
    }
}
