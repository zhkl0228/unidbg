package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.JniFunction;

public class ProxyDvmClass extends DvmClass {

    protected ProxyDvmClass(BaseVM vm, String className, DvmClass superClass, DvmClass[] interfaceClasses, ProxyClassLoader classLoader, ProxyDvmObjectVisitor visitor) {
        super(vm, className, superClass, interfaceClasses, null);

        setJni(createJni(classLoader, visitor));

        try {
            this.value = classLoader.loadClass(getName());
        } catch (ClassNotFoundException ignored) {
        }
    }

    protected JniFunction createJni(ProxyClassLoader classLoader, ProxyDvmObjectVisitor visitor) {
        return new ProxyJni(classLoader, visitor);
    }

}
