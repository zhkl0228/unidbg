package cn.banny.emulator.linux.android.dvm.api;

import cn.banny.emulator.linux.android.dvm.DvmClass;
import cn.banny.emulator.linux.android.dvm.DvmObject;

public class Binder extends DvmObject<String> {

    public Binder(DvmClass objectType, String value) {
        super(objectType, value);
    }

}
