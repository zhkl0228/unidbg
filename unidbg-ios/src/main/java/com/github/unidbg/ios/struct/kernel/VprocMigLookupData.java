package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VprocMigLookupData extends UnidbgStructure {

    public VprocMigLookupData(Pointer p) {
        super(p);
    }

    public int ret;
    public int size;
    public AuditToken au_tok;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ret", "size", "au_tok");
    }

}
