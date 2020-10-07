package com.github.unidbg.ios.struct.attr;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Collections;
import java.util.List;

public class UserAccess extends UnidbgStructure {

    public UserAccess(Pointer p) {
        super(p);
    }

    public int mode;

    @Override
    protected List<String> getFieldOrder() {
        return Collections.singletonList("mode");
    }

}
