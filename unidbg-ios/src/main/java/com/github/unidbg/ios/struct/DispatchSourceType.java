package com.github.unidbg.ios.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class DispatchSourceType extends UnidbgStructure {

    public DispatchSourceType(Pointer p) {
        super(p);
        unpack();
    }

    public KEvent64 ke;
    public long mask;
    public long init;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ke", "mask", "init");
    }

}
