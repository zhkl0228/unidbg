package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.linux.android.dvm.VM;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Member;
import java.lang.reflect.Method;

class ProxyMethod implements ProxyCall {

    private final ProxyDvmObjectVisitor visitor;
    private final Member method;
    private final Object[] args;

    ProxyMethod(ProxyDvmObjectVisitor visitor, Member method, Object[] args) {
        this.visitor = visitor;
        this.method = method;
        this.args = args;
    }

    @Override
    public Object call(VM vm, Object obj) throws IllegalAccessException, InvocationTargetException {
        try {
            patchClassName(obj, args);

            if (visitor != null) {
                visitor.onProxyVisit(method, obj, args);
            }
            if (method instanceof Method) {
                Object result = ((Method) method).invoke(obj, args);
                if (visitor != null) {
                    result = visitor.postProxyVisit(method, obj, args, result);
                }
                return result;
            }
            throw new UnsupportedOperationException("method=" + method);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getTargetException();
            if (cause instanceof BackendException) {
                throw (BackendException) cause;
            }
            if (cause instanceof ProxyDvmException) {
                vm.throwException(ProxyDvmObject.createObject(vm, cause));
                return null;
            }
            if (cause instanceof ClassNotFoundException) {
                vm.throwException(ProxyDvmObject.createObject(vm, cause));
                return null;
            }
            throw e;
        }
    }

    private void patchClassName(Object obj, Object[] args) {
        if (obj instanceof ClassLoader &&
                args.length == 1 &&
                ("loadClass".equals(method.getName()) || "findClass".equals(method.getName()))) {
            String binaryName = (String) args[0];
            args[0] = binaryName.replace('/', '.');
        }
    }
}
