package com.github.unidbg.file.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.ios.struct.attr.AttrList;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.sun.jna.Pointer;

public interface DarwinFileIO extends NewFileIO {

    int F_GETPATH = 50; /* return the full path of the fd */

    int ATTR_BIT_MAP_COUNT = 5;
    int ATTR_CMN_CRTIME = 0x00000200;
    int ATTR_CMN_FNDRINFO = 0x00004000;
    int ATTR_CMN_USERACCESS = 0x00200000; // (used to get the user's access mode to the file).

    int X_OK = 1;
    int W_OK = 2;
    int R_OK = 4;

    int F_GETPROTECTIONCLASS =	63;	/* Get the protection class of a file from the EA, returns int */
    int F_SETPROTECTIONCLASS =	64; /* Set the protection class of a file for the EA, requires int */

    int fstat(Emulator<?> emulator, StatStructure stat);

    int fstatfs(StatFS statFS);

    int getattrlist(AttrList attrList, Pointer attrBuf, int attrBufSize);

    int getdirentries64(Pointer buf, int bufSize);
}
