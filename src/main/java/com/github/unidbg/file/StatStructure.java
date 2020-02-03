package com.github.unidbg.file;

import com.github.unidbg.pointer.UnicornStructure;
import com.github.unidbg.unix.struct.TimeSpec;
import com.sun.jna.Pointer;

public abstract class StatStructure extends UnicornStructure {

    public StatStructure(Pointer p) {
        super(p);
    }

    public int st_dev; /* [XSI] ID of device containing file */
    public short st_mode; /* [XSI] Mode of file (see below) */
    public short st_nlink; /* [XSI] Number of hard links */
    public Pointer st_ino; /* [XSI] File serial number */

    public int st_uid; /* [XSI] User ID of the file */
    public int st_gid; /* [XSI] Group ID of the file */
    public int st_rdev; /* [XSI] Device ID */

    public TimeSpec st_atimespec; /* time of last access */
    public TimeSpec st_mtimespec; /* time of last data modification */
    public TimeSpec st_ctimespec; /* time of last status change */
    public TimeSpec st_birthtimespec; /* time of file creation(birth) */

    public Pointer st_size; /* [XSI] file size, in bytes */
    public Pointer st_blocks; /* [XSI] blocks allocated for file */
    public int st_blksize; /* [XSI] optimal blocksize for I/O */

    public int st_flags; /* user defined flags for file */
    public int st_gen; /* file generation number */

}
