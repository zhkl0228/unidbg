package com.github.unidbg.ios.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class KEvent64 extends UnidbgStructure {

    public KEvent64(Pointer p) {
        super(p);
    }

    public long ident; /* identifier for this event */
    public short filter; /* filter for event */
    public short flags; /* general flags */
    public int fflags; /* filter-specific flags */
    public long data; /* filter-specific data */
    public long udata; /* opaque user data identifier */
    public long[] ext = new long[2]; /* filter-specific extensions */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ident", "filter", "flags", "fflags", "data", "udata", "ext");
    }

}
