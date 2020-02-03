package com.github.unidbg.ios.struct;

import com.sun.jna.Pointer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SegmentCommand extends LoadCommand {

    public SegmentCommand(Pointer p) {
        super(p);
    }

    public byte[] segname = new byte[16];
    public int vmaddr;

    @Override
    protected List<String> getFieldOrder() {
        List<String> list = new ArrayList<>(super.getFieldOrder());
        Collections.addAll(list, "segname", "vmaddr");
        return list;
    }
}
