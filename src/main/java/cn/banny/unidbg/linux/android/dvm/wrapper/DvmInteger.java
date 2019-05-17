package cn.banny.unidbg.linux.android.dvm.wrapper;

import cn.banny.unidbg.linux.android.dvm.DvmObject;
import cn.banny.unidbg.linux.android.dvm.VM;

public class DvmInteger extends DvmObject<Integer> {

    public static DvmInteger valueOf(VM vm, int i) {
        return new DvmInteger(vm, i);
    }

    private DvmInteger(VM vm, Integer value) {
        super(vm.resolveClass("java/lang/Integer"), value);
    }

}
