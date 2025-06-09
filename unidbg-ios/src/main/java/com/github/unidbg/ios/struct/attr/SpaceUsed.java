package com.github.unidbg.ios.struct.attr;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Collections;
import java.util.List;

public class SpaceUsed extends UnidbgStructure {

    public SpaceUsed(Pointer p) {
        super(p);
    }

    public long spaceused;

    @Override
    protected List<String> getFieldOrder() {
        return Collections.singletonList("spaceused");
    }
}
