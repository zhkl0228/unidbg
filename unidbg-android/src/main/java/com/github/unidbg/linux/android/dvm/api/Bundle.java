package com.github.unidbg.linux.android.dvm.api;

import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

import java.util.Properties;

public class Bundle extends DvmObject<Properties> {

    public Bundle(VM vm, Properties properties) {
        super(vm.resolveClass("android/os/Bundle"), properties);
    }

    public int getInt(String key) {
        String value = super.value.getProperty(key);
        if (value == null) {
            throw new BackendException("key=" + key);
        }

        return Integer.parseInt(value, 16);
    }
}
