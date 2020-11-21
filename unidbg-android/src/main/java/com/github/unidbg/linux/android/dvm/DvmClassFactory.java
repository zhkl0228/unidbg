package com.github.unidbg.linux.android.dvm;

public interface DvmClassFactory {

    DvmClass createClass(BaseVM vm, String className, DvmClass superClass, DvmClass[] interfaceClasses);

}
