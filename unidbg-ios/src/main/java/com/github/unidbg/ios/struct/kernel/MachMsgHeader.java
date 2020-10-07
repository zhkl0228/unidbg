package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.ios.DarwinSyscall;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class MachMsgHeader extends UnidbgStructure implements DarwinSyscall {

    public MachMsgHeader(Pointer p) {
        super(p);
    }

    public int msgh_bits;
    public int msgh_size;
    public int msgh_remote_port;
    public int msgh_local_port;
    public int msgh_voucher_port;
    public int msgh_id;

    public void setMsgBits(boolean complex) {
        msgh_bits &= 0xff;
        if (complex) {
            msgh_bits |= MACH_MSGH_BITS_COMPLEX;
        }
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("msgh_bits", "msgh_size", "msgh_remote_port", "msgh_local_port", "msgh_voucher_port", "msgh_id");
    }

}
