package com.github.unidbg.linux.struct;

import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class IFReq32 extends IFReq {

    IFReq32(Pointer p) {
        super(p);
    }

    public byte[] ifr_ifru = new byte[IFNAMSIZ];

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ifrn_name", "ifr_ifru");
    }

}
