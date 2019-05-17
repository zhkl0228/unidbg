package cn.banny.unidbg.linux.android.dvm.api;

import cn.banny.unidbg.linux.android.dvm.DvmClass;
import cn.banny.unidbg.linux.android.dvm.DvmObject;

public class ClassLoader extends DvmObject<String> {

    public ClassLoader(DvmClass objectType, String value) {
        super(objectType, value);
    }

}
