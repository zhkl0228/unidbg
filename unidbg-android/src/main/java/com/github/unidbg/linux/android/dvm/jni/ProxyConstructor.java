package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.linux.android.dvm.VM;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

class ProxyConstructor implements ProxyCall {

    private final ProxyDvmObjectVisitor visitor;
    private final Constructor<?> constructor;
    private final Object[] args;

    ProxyConstructor(ProxyDvmObjectVisitor visitor, Constructor<?> constructor, Object[] args) {
        this.visitor = visitor;
        this.constructor = constructor;
        this.args = args;
    }

    @Override
    public Object call(VM vm, Object obj) throws IllegalAccessException, InvocationTargetException, InstantiationException {
        try {
            Object inst = constructor.newInstance(args);
            if (visitor != null) {
                visitor.onProxyVisit(constructor, inst, args);
            }
            return inst;
        } catch (InvocationTargetException e) {
            Throwable cause = e.getTargetException();
            if (cause instanceof BackendException) {
                throw (BackendException) cause;
            }
            if (cause instanceof ProxyDvmException) {
                vm.throwException(ProxyDvmObject.createObject(vm, cause));
                return null;
            }
            throw e;
        }
    }

}
