package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.file.ios.StatStructure;
import com.github.unidbg.unix.struct.TimeSpec64;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class Stat64 extends StatStructure {

    public Stat64(Pointer p) {
        super(p);
        unpack();
    }

    public TimeSpec64 st_atimespec; /* time of last access */
    public TimeSpec64 st_mtimespec; /* time of last data modification */
    public TimeSpec64 st_ctimespec; /* time of last status change */
    public TimeSpec64 st_birthtimespec; /* time of file creation(birth) */

    @Override
    public void setSt_atimespec(long tv_sec, long tv_nsec) {
        st_atimespec.tv_sec = tv_sec;
        st_atimespec.tv_nsec = tv_nsec;
    }

    @Override
    public void setSt_mtimespec(long tv_sec, long tv_nsec) {
        st_mtimespec.tv_sec = tv_sec;
        st_mtimespec.tv_nsec = tv_nsec;
    }

    @Override
    public void setSt_ctimespec(long tv_sec, long tv_nsec) {
        st_ctimespec.tv_sec = tv_sec;
        st_ctimespec.tv_nsec = tv_nsec;
    }

    @Override
    public void setSt_birthtimespec(long tv_sec, long tv_nsec) {
        st_birthtimespec.tv_sec = tv_sec;
        st_birthtimespec.tv_nsec = tv_nsec;
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("st_dev", "st_mode", "st_nlink", "st_ino", "st_uid", "st_gid", "st_rdev",
                "st_atimespec", "st_mtimespec", "st_ctimespec", "st_birthtimespec",
                "st_size", "st_blocks", "st_blksize", "st_flags", "st_gen");
    }

}
