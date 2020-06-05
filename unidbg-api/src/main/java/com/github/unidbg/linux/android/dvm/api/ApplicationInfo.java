package com.github.unidbg.linux.android.dvm.api;

import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

public class ApplicationInfo extends DvmObject<Object> {

    public ApplicationInfo(VM vm) {
        super(vm.resolveClass("android/content/pm/ApplicationInfo"), null);
    }

}
