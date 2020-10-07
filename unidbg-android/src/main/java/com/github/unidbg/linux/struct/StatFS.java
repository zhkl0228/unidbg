package com.github.unidbg.linux.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public abstract class StatFS extends UnidbgStructure {

    protected StatFS(Pointer p) {
        super(p);
    }

    public abstract void setType(int type);
    public abstract void setBlockSize(int size);
    public abstract void setNameLen(int namelen);
    public abstract void setFrSize(int frsize);
    public abstract void setFlags(int flags);

    public long f_blocks;
    public long f_bfree;
    public long f_bavail;
    public long f_files;
    public long f_ffree;
    public int[] f_fsid = new int[2];

    @Override
    protected final List<String> getFieldOrder() {
        return Arrays.asList("f_type", "f_bsize", "f_blocks", "f_bfree", "f_bavail", "f_files", "f_ffree",
                "f_fsid", "f_namelen", "f_frsize", "f_flags", "f_spare");
    }

}
