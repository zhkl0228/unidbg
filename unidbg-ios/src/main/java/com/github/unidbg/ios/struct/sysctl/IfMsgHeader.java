package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public final class IfMsgHeader extends UnidbgStructure {

    public IfMsgHeader(Pointer p) {
        super(p);
    }

    public short	ifm_msglen;	/* to skip non-understood messages */
    public byte     ifm_version;	/* future binary compatability */
    public byte     ifm_type;	/* message type */
    public int		ifm_addrs;	/* like rtm_addrs */
    public int		ifm_flags;	/* value of if_flags */
    public short	ifm_index;	/* index for associated ifp */
    public IfData   ifm_data;	/* statistics and other data about if */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ifm_msglen", "ifm_version", "ifm_type", "ifm_addrs", "ifm_flags", "ifm_index", "ifm_data");
    }

}
