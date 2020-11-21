package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmClassFactory;

public class ProxyClassFactory implements DvmClassFactory {

    private final ProxyClassLoader classLoader;

    public ProxyClassFactory() {
        this(ProxyClassFactory.class.getClassLoader());
    }

    public ProxyClassFactory(ClassLoader classLoader) {
        this.classLoader = new ProxyClassLoader(classLoader);
    }

    public DvmClassFactory configClassNameMapper(ProxyClassMapper mapper) {
        classLoader.setClassNameMapper(mapper);
        return this;
    }

    private ProxyDvmObjectVisitor visitor;

    public DvmClassFactory configObjectVisitor(ProxyDvmObjectVisitor visitor) {
        this.visitor = visitor;
        return this;
    }

    @Override
    public DvmClass createClass(BaseVM vm, String className, DvmClass superClass, DvmClass[] interfaceClasses) {
        return new ProxyDvmClass(vm, className, superClass, interfaceClasses, classLoader, visitor);
    }

}
