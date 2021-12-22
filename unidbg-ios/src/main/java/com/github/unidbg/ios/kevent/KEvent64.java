package com.github.unidbg.ios.kevent;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

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

    public void copy(KEvent64 pending) {
        this.ident = pending.ident;
        this.filter = pending.filter;
        this.flags = pending.flags;
        this.fflags = pending.fflags;
        this.data = pending.data;
        this.udata = pending.udata;
        this.ext = pending.ext;
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ident", "filter", "flags", "fflags", "data", "udata", "ext");
    }

    @Override
    public int hashCode() {
        return Objects.hash(ident, filter);
    }

}
