package com.github.unidbg.ios.struct.attr;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Collections;
import java.util.List;

public class Dev extends UnicornStructure {

    public Dev(Pointer p) {
        super(p);
    }

    public int dev;

    @Override
    protected List<String> getFieldOrder() {
        return Collections.singletonList("dev");
    }

}
