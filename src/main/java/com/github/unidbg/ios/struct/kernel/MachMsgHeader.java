package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class MachMsgHeader extends UnicornStructure {

    public MachMsgHeader(Pointer p) {
        super(p);
    }

    public int msgh_bits;
    public int msgh_size;
    public int msgh_remote_port;
    public int msgh_local_port;
    public int msgh_voucher_port;
    public int msgh_id;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("msgh_bits", "msgh_size", "msgh_remote_port", "msgh_local_port", "msgh_voucher_port", "msgh_id");
    }

}
