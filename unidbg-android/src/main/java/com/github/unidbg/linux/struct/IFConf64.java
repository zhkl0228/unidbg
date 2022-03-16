package com.github.unidbg.linux.struct;

import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class IFConf64 extends IFConf {

    public IFConf64(Pointer p) {
        super(p);
        unpack();
    }

    @Override
    public long getIfcuReq() {
        return ifcu_req;
    }

    public long ifcu_req; // ptr

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ifc_len", "ifcu_req");
    }

}
