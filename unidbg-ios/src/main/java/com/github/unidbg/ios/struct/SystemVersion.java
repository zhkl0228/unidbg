package com.github.unidbg.ios.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

/**
 * struct os_system_version_s
 */
public class SystemVersion extends UnidbgStructure {

    public int major;
    public int minor;
    public int patch;

    public SystemVersion(Pointer p) {
        super(p);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("major", "minor", "patch");
    }

}
