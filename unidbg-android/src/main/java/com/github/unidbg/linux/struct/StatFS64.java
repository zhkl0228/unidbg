package com.github.unidbg.linux.struct;

import com.sun.jna.Pointer;

public class StatFS64 extends StatFS {

    public StatFS64(Pointer p) {
        super(p);
    }

    public long f_type;
    public long f_bsize;
    public long f_namelen;
    public long f_frsize;
    public long f_flags;
    public long[] f_spare = new long[4];

    @Override
    public void setType(int type) {
        f_type = type;
    }

    @Override
    public void setBlockSize(int size) {
        this.f_bsize = size;
    }

    @Override
    public void setNameLen(int namelen) {
        this.f_namelen = namelen;
    }

    @Override
    public void setFrSize(int frsize) {
        this.f_frsize = frsize;
    }

    @Override
    public void setFlags(int flags) {
        this.f_flags = flags;
    }

}
