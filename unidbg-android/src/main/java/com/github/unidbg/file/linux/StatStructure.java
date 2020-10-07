package com.github.unidbg.file.linux;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

public abstract class StatStructure extends UnidbgStructure {

    public StatStructure(Pointer p) {
        super(p);
    }

    public long st_dev;
    public long st_ino;
    public int st_mode;
    public int st_nlink;
    public int st_uid;
    public int st_gid;
    public long st_rdev;
    public long st_size;
    public int st_blksize;
    public long st_blocks;

    /**
     * @param st_atim millis
     */
    public abstract void setSt_atim(long st_atim, long tv_nsec);

    /**
     * @param st_mtim millis
     */
    public abstract void setSt_mtim(long st_mtim, long tv_nsec);

    /**
     * @param st_ctim millis
     */
    public abstract void setSt_ctim(long st_ctim, long tv_nsec);

    /**
     * @param lastModified millis
     */
    public final void setLastModification(long lastModified) {
        setLastModification(lastModified, 0L);
    }

    /**
     * @param lastModified millis
     */
    public final void setLastModification(long lastModified, long tv_nsec) {
        setSt_atim(lastModified, tv_nsec);
        setSt_mtim(lastModified, tv_nsec);
        setSt_ctim(lastModified, tv_nsec);
    }

}
