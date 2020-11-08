package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmClassFactory;

public class ProxyClassFactory implements DvmClassFactory {

    private final ClassLoader classLoader;

    public ProxyClassFactory() {
        this(ProxyClassFactory.class.getClassLoader());
    }

    public ProxyClassFactory(ClassLoader classLoader) {
        this.classLoader = classLoader;
    }

    @Override
    public DvmClass createClass(BaseVM vm, String className, DvmClass[] interfaceClasses) {
        return new ProxyDvmClass(vm, className, interfaceClasses, classLoader);
    }

}
