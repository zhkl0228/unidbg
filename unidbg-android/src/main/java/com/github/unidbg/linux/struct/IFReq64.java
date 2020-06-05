package com.github.unidbg.linux.struct;

import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class IFReq64 extends IFReq {

    IFReq64(Pointer p) {
        super(p);
    }

    public byte[] ifr_ifru = new byte[IFNAMSIZ + 8];

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ifrn_name", "ifr_ifru");
    }

}
