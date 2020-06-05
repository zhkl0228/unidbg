package com.github.unidbg.ios.struct;

import com.sun.jna.Pointer;

import java.util.ArrayList;
import java.util.List;

public class MachHeader64 extends MachHeader {

    public MachHeader64(Pointer p) {
        super(p);
    }

    public int reserved;

    @Override
    protected List<String> getFieldOrder() {
        List<String> list = new ArrayList<>(super.getFieldOrder());
        list.add("reserved");
        return list;
    }
}
