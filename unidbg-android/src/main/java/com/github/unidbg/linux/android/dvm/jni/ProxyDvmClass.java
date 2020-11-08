package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmClass;

class ProxyDvmClass extends DvmClass {

    private static Class<?> getClassValue(ClassLoader classLoader, String className) {
        try {
            return classLoader.loadClass(className.replace('/', '.'));
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    ProxyDvmClass(BaseVM vm, String className, DvmClass[] interfaceClasses, ClassLoader classLoader) {
        super(vm, className, interfaceClasses, getClassValue(classLoader, className));

        setJni(new ProxyJni(classLoader));
    }

}
