package cn.banny.unidbg.linux.android.dvm.api;

import cn.banny.unidbg.linux.android.dvm.DvmObject;
import cn.banny.unidbg.linux.android.dvm.VM;

public class AssetManager extends DvmObject<String> {

    public AssetManager(VM vm, String value) {
        super(vm.resolveClass("android/content/res/AssetManager"), value);
    }

}
