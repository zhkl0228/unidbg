package com.github.unidbg.linux.android.dvm.jni;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

class ProxyConstructor implements ProxyCall {

    private final Constructor<?> constructor;
    private final Object[] args;

    ProxyConstructor(Constructor<?> constructor, Object[] args) {
        this.constructor = constructor;
        this.args = args;
    }

    @Override
    public Object call(Object obj) throws IllegalAccessException, InvocationTargetException, InstantiationException {
        constructor.setAccessible(true);
        return constructor.newInstance(args);
    }

}
