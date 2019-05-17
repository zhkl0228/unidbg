package cn.banny.unidbg.linux.android.dvm.api;

import cn.banny.unidbg.linux.android.dvm.DvmObject;
import cn.banny.unidbg.linux.android.dvm.VM;

public class ClassLoader extends DvmObject<String> {

    public ClassLoader(VM vm, String value) {
        super(vm.resolveClass("dalvik/system/PathClassLoader"), value);
    }

}
