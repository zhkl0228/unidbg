package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Collections;
import java.util.List;

public class AuditToken extends UnidbgStructure {

    public AuditToken(Pointer p) {
        super(p);
    }

    public int[] val = new int[8];

    @Override
    protected List<String> getFieldOrder() {
        return Collections.singletonList("val");
    }

}
