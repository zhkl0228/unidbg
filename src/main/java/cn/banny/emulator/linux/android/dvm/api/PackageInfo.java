package cn.banny.emulator.linux.android.dvm.api;

import cn.banny.emulator.linux.android.dvm.DvmObject;
import cn.banny.emulator.linux.android.dvm.VM;

public class PackageInfo extends DvmObject<String> {

    private final int flags;

    public PackageInfo(VM vm, String packageName, int flags) {
        super(vm.resolveClass("android/content/pm/PackageInfo"), packageName);
        this.flags = flags;
    }

    public String getPackageName() {
        return getValue();
    }

    public int getFlags() {
        return flags;
    }
}
