package com.github.unidbg.linux.android.dvm.api;

import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

public class AssetManager extends DvmObject<String> {

    public AssetManager(VM vm, String value) {
        super(vm.resolveClass("android/content/res/AssetManager"), value);
    }

}
