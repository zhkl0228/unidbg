package cn.banny.unidbg.linux.android.dvm.api;

import cn.banny.unidbg.linux.android.dvm.DvmObject;
import cn.banny.unidbg.linux.android.dvm.VM;
import unicorn.UnicornException;

import java.util.Properties;

public class Bundle extends DvmObject<Properties> {

    public Bundle(VM vm, Properties properties) {
        super(vm.resolveClass("android/os/Bundle"), properties);
    }

    public int getInt(String key) {
        String value = super.value.getProperty(key);
        if (value == null) {
            throw new UnicornException("key=" + key);
        }

        return Integer.parseInt(value, 16);
    }
}
