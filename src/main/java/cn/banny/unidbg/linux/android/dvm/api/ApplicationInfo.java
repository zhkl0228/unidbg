package cn.banny.unidbg.linux.android.dvm.api;

import cn.banny.unidbg.linux.android.dvm.DvmObject;
import cn.banny.unidbg.linux.android.dvm.VM;

public class ApplicationInfo extends DvmObject<Object> {

    public ApplicationInfo(VM vm) {
        super(vm.resolveClass("android/content/pm/ApplicationInfo"), null);
    }

}
