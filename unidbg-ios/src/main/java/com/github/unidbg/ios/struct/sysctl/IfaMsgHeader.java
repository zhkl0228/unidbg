package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public final class IfaMsgHeader extends UnidbgStructure {

    public IfaMsgHeader(Pointer p) {
        super(p);
    }

    public short ifam_msglen;    /* to skip non-understood messages */
    public byte ifam_version;   /* future binary compatability */
    public byte ifam_type;      /* message type */
    public int ifam_addrs;     /* like rtm_addrs */
    public int ifam_flags;     /* value of ifa_flags */
    public short ifam_index;     /* index for associated ifp */
    public int ifam_metric;    /* value of ifa_metric */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ifam_msglen", "ifam_version", "ifam_type", "ifam_addrs", "ifam_flags", "ifam_index", "ifam_metric");
    }

}
