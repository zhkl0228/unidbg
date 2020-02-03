package com.github.unidbg.linux.android.dvm.api;

import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

public class ClassLoader extends DvmObject<String> {

    public ClassLoader(VM vm, String value) {
        super(vm.resolveClass("dalvik/system/PathClassLoader"), value);
    }

}
