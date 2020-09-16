package com.github.unidbg.linux.android.dvm.api;

import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

public class Binder extends DvmObject<String> {

    public Binder(VM vm, String value) {
        super(vm.resolveClass("android/os/IBinder"), value);
    }

}
