package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.VM;
import unicorn.UnicornException;

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
    public Object call(VM vm, Object obj) throws IllegalAccessException, InvocationTargetException, InstantiationException {
        try {
            return constructor.newInstance(args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getTargetException();
            if (cause instanceof UnicornException) {
                throw (UnicornException) cause;
            }
            if (cause instanceof ProxyDvmException) {
                vm.throwException(ProxyDvmObject.createObject(vm, cause));
                return null;
            }
            throw e;
        }
    }

}
