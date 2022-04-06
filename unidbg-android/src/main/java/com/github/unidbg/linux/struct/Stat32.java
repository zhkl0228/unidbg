package com.github.unidbg.linux.struct;

import com.github.unidbg.file.linux.StatStructure;
import com.github.unidbg.unix.struct.TimeSpec32;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class Stat32 extends StatStructure {

    public Stat32(Pointer p) {
        super(p);
    }

    public byte[] __pad0 = new byte[4];
    public int __st_ino;
    public byte[] __pad3 = new byte[4];
    public TimeSpec32 st_atim;
    public TimeSpec32 st_mtim;
    public TimeSpec32 st_ctim;

    @Override
    public void setSt_atim(long st_atim, long tv_nsec) {
        this.st_atim.tv_sec = (int) (st_atim / 1000L);
        this.st_atim.tv_nsec = (int) ((st_atim % 1000) * 1000000L + (tv_nsec % 1000000L));
    }

    @Override
    public void setSt_mtim(long st_mtim, long tv_nsec) {
        this.st_mtim.tv_sec = (int) (st_mtim / 1000L);
        this.st_mtim.tv_nsec = (int) ((st_mtim % 1000) * 1000000L + tv_nsec % 1000000L);
    }

    @Override
    public void setSt_ctim(long st_ctim, long tv_nsec) {
        this.st_ctim.tv_sec = (int) (st_ctim / 1000L);
        this.st_ctim.tv_nsec = (int) ((st_ctim % 1000) * 1000000L + tv_nsec % 1000000L);
    }

    @Override
    public void setSt_ino(long st_ino) {
        super.setSt_ino(st_ino);
        __st_ino = (int) st_ino;
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("st_dev", "__pad0", "__st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_rdev", "__pad3",
                "st_size", "st_blksize", "st_blocks", "st_atim", "st_mtim", "st_ctim", "st_ino");
    }

}
