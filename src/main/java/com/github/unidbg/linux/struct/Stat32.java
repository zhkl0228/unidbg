package com.github.unidbg.linux.struct;

import com.github.unidbg.file.linux.StatStructure;
import com.github.unidbg.unix.struct.TimeSpec;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class Stat32 extends StatStructure {

    public Stat32(Pointer p) {
        super(p);
    }

    public byte[] __pad0 = new byte[4];
    public int __st_ino;
    public int st_mode;
    public int st_nlink;
    public int st_uid;
    public int st_gid;
    public byte[] __pad3 = new byte[4];
    public int st_blksize;
    public long st_blocks;
    public TimeSpec st_atim;
    public TimeSpec st_mtim;
    public TimeSpec st_ctim;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("st_dev", "__pad0", "__st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_rdev", "__pad3",
                "st_size", "st_blksize", "st_blocks", "st_atim", "st_mtim", "st_ctim", "st_ino");
    }

}
