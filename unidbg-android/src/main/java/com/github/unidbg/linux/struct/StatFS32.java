package com.github.unidbg.linux.struct;

import com.sun.jna.Pointer;

public class StatFS32 extends StatFS {

    public StatFS32(Pointer p) {
        super(p);
    }

    public int f_type;
    public int f_bsize;
    public int f_namelen;
    public int f_frsize;
    public int f_flags;
    public int[] f_spare = new int[4];

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
