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
    public void setSt_atim(long st_atim, long tv_nsec) {
        this.st_atim.tv_sec = st_atim / 1000L;
        this.st_atim.tv_nsec = (st_atim % 1000) * 1000000L + (tv_nsec % 1000000L);
    }

    @Override
    public void setSt_mtim(long st_mtim, long tv_nsec) {
        this.st_mtim.tv_sec = st_mtim / 1000L;
        this.st_mtim.tv_nsec = (st_mtim % 1000) * 1000000L + (tv_nsec % 1000000L);
    }

    @Override
    public void setSt_ctim(long st_ctim, long tv_nsec) {
        this.st_ctim.tv_sec = st_ctim / 1000L;
        this.st_ctim.tv_nsec = (st_ctim % 1000) * 1000000L + (tv_nsec % 1000000L);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_rdev", "__pad1", "st_size", "st_blksize",
                "__pad2", "st_blocks", "st_atim", "st_mtim", "st_ctim", "__unused4", "__unused5");
    }

}
