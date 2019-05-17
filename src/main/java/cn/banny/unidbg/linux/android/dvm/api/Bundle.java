package cn.banny.unidbg.linux.android.dvm.api;

import cn.banny.unidbg.linux.android.dvm.DvmClass;
import cn.banny.unidbg.linux.android.dvm.DvmObject;
import unicorn.UnicornException;

import java.util.Properties;

public class Bundle extends DvmObject<Properties> {

    public Bundle(DvmClass objectType, Properties properties) {
        super(objectType, properties);
    }

    public int getInt(String key) {
        String value = super.value.getProperty(key);
        if (value == null) {
            throw new UnicornException("key=" + key);
        }

        return Integer.parseInt(value, 16);
    }
}
