package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class StatFS extends UnidbgStructure {

    private static final int MFSTYPENAMELEN = 16; /* length of fs type name including null */
    private static final int MAXPATHLEN = 1024; /* max bytes in pathname */

    public StatFS(Pointer p) {
        super(p);
    }

    public int f_bsize; /* fundamental file system block size */
    public int f_iosize; /* optimal transfer block size */
    public long f_blocks; /* total data blocks in file system */
    public long f_bfree; /* free blocks in fs */
    public long f_bavail; /* free blocks avail to non-superuser */
    public long f_files; /* total file nodes in file system */
    public long f_ffree; /* free file nodes in fs */

    public long f_fsid; /* file system id */
    public int f_owner; /* user that mounted the filesystem */
    public int f_type; /* type of filesystem */
    public int f_flags; /* copy of mount exported flags */
    public int f_fssubtype; /* fs sub-type (flavor) */

    public byte[] f_fstypename = new byte[MFSTYPENAMELEN]; /* fs type name */
    public byte[] f_mntonname = new byte[MAXPATHLEN]; /* directory on which mounted */
    public byte[] f_mntfromname = new byte[MAXPATHLEN]; /* mounted filesystem */
    public int[] f_reserved = new int[8]; /* For future use */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("f_bsize", "f_iosize", "f_blocks", "f_bfree", "f_bavail", "f_files", "f_ffree", "f_fsid", "f_owner",
                "f_type", "f_flags", "f_fssubtype", "f_fstypename", "f_mntonname", "f_mntfromname", "f_reserved");
    }

}
