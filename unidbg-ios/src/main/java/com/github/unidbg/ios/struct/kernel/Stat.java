package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.file.ios.StatStructure;
import com.github.unidbg.unix.struct.TimeSpec;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public final class Stat extends StatStructure {

    public Stat(Pointer p) {
        super(p);
        setAlignType(Structure.ALIGN_NONE);
        unpack();
    }

    public TimeSpec st_atimespec; /* time of last access */
    public TimeSpec st_mtimespec; /* time of last data modification */
    public TimeSpec st_ctimespec; /* time of last status change */
    public TimeSpec st_birthtimespec; /* time of file creation(birth) */

    @Override
    public void setSt_atimespec(long lastModified) {
        st_atimespec.tv_sec = (int) (lastModified / 1000L);
        st_atimespec.tv_nsec = (int) ((lastModified % 1000) * 1000000L);
    }

    @Override
    public void setSt_mtimespec(long lastModified) {
        st_mtimespec.tv_sec = (int) (lastModified / 1000L);
        st_mtimespec.tv_nsec = (int) ((lastModified % 1000) * 1000000L);
    }

    @Override
    public void setSt_ctimespec(long lastModified) {
        st_ctimespec.tv_sec = (int) (lastModified / 1000L);
        st_ctimespec.tv_nsec = (int) ((lastModified % 1000) * 1000000L);
    }

    @Override
    public void setSt_birthtimespec(long lastModified) {
        st_birthtimespec.tv_sec = (int) (lastModified / 1000L);
        st_birthtimespec.tv_nsec = (int) ((lastModified % 1000) * 1000000L);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("st_dev", "st_mode", "st_nlink", "st_ino", "st_uid", "st_gid", "st_rdev",
                "st_atimespec", "st_mtimespec", "st_ctimespec", "st_birthtimespec",
                "st_size", "st_blocks", "st_blksize", "st_flags", "st_gen");
    }

}
