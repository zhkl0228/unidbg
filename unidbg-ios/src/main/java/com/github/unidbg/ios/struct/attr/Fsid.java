package com.github.unidbg.ios.struct.attr;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Collections;
import java.util.List;

public class Fsid extends UnidbgStructure {

    public Fsid(Pointer p) {
        super(p);
    }

    public int[] val = new int[2];	/* file system id type */

    @Override
    protected List<String> getFieldOrder() {
        return Collections.singletonList("val");
    }

}
