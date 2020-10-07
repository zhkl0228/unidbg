package com.github.unidbg.ios.struct.attr;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Collections;
import java.util.List;

public class FinderInfo extends UnidbgStructure {

    public FinderInfo(Pointer p) {
        super(p);
    }

    public byte[] finderInfo = new byte[32];

    @Override
    protected List<String> getFieldOrder() {
        return Collections.singletonList("finderInfo");
    }

}
