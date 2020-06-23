package com.github.unidbg.file.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.ios.struct.attr.AttrList;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.sun.jna.Pointer;

public interface DarwinFileIO extends NewFileIO {

    int F_NOCACHE = 48; /* turn data caching off/on for this fd */
    int F_GETPATH = 50; /* return the full path of the fd */

    /*
     * Vnode types.  VNON means no type.
     */
    enum vtype	{ VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VBAD, VSTR, VCPLX };

    int ATTR_BIT_MAP_COUNT = 5;
    int ATTR_CMN_NAME = 0x00000001;
    int ATTR_CMN_DEVID = 0x00000002;
    int ATTR_CMN_FSID = 0x00000004;
    int ATTR_CMN_OBJTYPE = 0x00000008;
    int ATTR_CMN_OBJID = 0x00000020;
    int ATTR_CMN_CRTIME = 0x00000200;
    int ATTR_CMN_FNDRINFO = 0x00004000;
    int ATTR_CMN_USERACCESS = 0x00200000; // (used to get the user's access mode to the file).

    int X_OK = 1;
    int W_OK = 2;
    int R_OK = 4;

    int F_GETPROTECTIONCLASS =	63;	/* Get the protection class of a file from the EA, returns int */
    int F_SETPROTECTIONCLASS =	64; /* Set the protection class of a file for the EA, requires int */

    int XATTR_NOFOLLOW =   0x0001;     /* Don't follow symbolic links */
    int XATTR_CREATE =     0x0002;     /* set the value, fail if attr already exists */
    int XATTR_REPLACE =    0x0004;     /* set the value, fail if attr does not exist */

    int fstat(Emulator<?> emulator, StatStructure stat);

    int fstatfs(StatFS statFS);

    int getattrlist(AttrList attrList, Pointer attrBuf, int attrBufSize);
    int setattrlist(AttrList attrList, Pointer attrBuf, int attrBufSize);

    int getdirentries64(Pointer buf, int bufSize);

    int listxattr(Pointer namebuf, int size, int options);
    int setxattr(String name, byte[] data);
    int getxattr(Emulator<?> emulator, String name, Pointer value, int size);
    int chown(int uid, int gid);
    int chmod(int mode);
    int chflags(int flags);

}
