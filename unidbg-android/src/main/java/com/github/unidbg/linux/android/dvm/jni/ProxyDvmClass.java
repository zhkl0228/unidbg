package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmClass;

class ProxyDvmClass extends DvmClass {

    ProxyDvmClass(BaseVM vm, String className, DvmClass[] interfaceClasses, ClassLoader classLoader) {
        super(vm, className, interfaceClasses);

        setJni(new ProxyJni(classLoader));
    }

}
