package com.github.unidbg.linux.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class IFConf extends UnidbgStructure {

    public IFConf(Pointer p) {
        super(p);
        unpack();
    }

    public int ifc_len;
    public Pointer ifcu_req;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ifc_len", "ifcu_req");
    }

}
