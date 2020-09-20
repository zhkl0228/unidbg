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
    public void setLastModification(long lastModified) {
        for (TimeSpec64 spec : Arrays.asList(st_atimespec, st_mtimespec, st_ctimespec, st_birthtimespec)) {
            spec.tv_sec = lastModified / 1000L;
            spec.tv_nsec = (lastModified % 1000) * 1000000L;
        }
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("st_dev", "st_mode", "st_nlink", "st_ino", "st_uid", "st_gid", "st_rdev",
                "st_atimespec", "st_mtimespec", "st_ctimespec", "st_birthtimespec",
                "st_size", "st_blocks", "st_blksize", "st_flags", "st_gen");
    }

}
