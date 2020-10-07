package com.github.unidbg.file.ios;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

public abstract class StatStructure extends UnidbgStructure {

    public StatStructure(Pointer p) {
        super(p);
    }

    public int st_dev; /* [XSI] ID of device containing file */
    public short st_mode; /* [XSI] Mode of file (see below) */
    public short st_nlink; /* [XSI] Number of hard links */
    public long st_ino; /* [XSI] File serial number */

    public int st_uid; /* [XSI] User ID of the file */
    public int st_gid; /* [XSI] Group ID of the file */
    public int st_rdev; /* [XSI] Device ID */

    public long st_size; /* [XSI] file size, in bytes */
    public long st_blocks; /* [XSI] blocks allocated for file */
    public int st_blksize; /* [XSI] optimal blocksize for I/O */

    public int st_flags; /* user defined flags for file */
    public int st_gen; /* file generation number */

    public void setSize(long size) {
        this.st_size = size;
    }

    public void setBlockCount(long count) {
        this.st_blocks = count;
    }

    public abstract void setLastModification(long lastModified);

}
