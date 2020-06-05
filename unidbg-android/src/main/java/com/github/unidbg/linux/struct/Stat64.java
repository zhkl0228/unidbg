package com.github.unidbg.linux.struct;

import com.github.unidbg.file.linux.StatStructure;
import com.github.unidbg.unix.struct.TimeSpec64;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class Stat64 extends StatStructure {

    public Stat64(Pointer p) {
        super(p);
    }

    public long __pad1;
    public int __pad2;
    public TimeSpec64 st_atim;
    public TimeSpec64 st_mtim;
    public TimeSpec64 st_ctim;
    public int __unused4;
    public int __unused5;

    @Override
    public void setLastModification(long lastModified) {
        for (TimeSpec64 spec : Arrays.asList(st_atim, st_mtim, st_ctim)) {
            spec.tv_sec = lastModified / 1000L;
            spec.tv_nsec = (lastModified % 1000) * 1000;
        }
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_rdev", "__pad1", "st_size", "st_blksize",
                "__pad2", "st_blocks", "st_atim", "st_mtim", "st_ctim", "__unused4", "__unused5");
    }

}
