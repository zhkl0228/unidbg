package com.github.unidbg.linux.android;

import com.sun.jna.Pointer;

public interface SystemPropertyProvider {

    String getProperty(String key);

    default Pointer __system_property_find(String key) {
        return null;
    }

}
