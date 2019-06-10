package cn.banny.unidbg.linux.android.dvm.wrapper;

import cn.banny.unidbg.linux.android.dvm.DvmObject;
import cn.banny.unidbg.linux.android.dvm.VM;

public class DvmBoolean extends DvmObject<Boolean> {

    public static DvmBoolean valueOf(VM vm, boolean b) {
        return new DvmBoolean(vm, b);
    }

    private DvmBoolean(VM vm, Boolean value) {
        super(vm.resolveClass("java/lang/Boolean"), value);
    }

}
