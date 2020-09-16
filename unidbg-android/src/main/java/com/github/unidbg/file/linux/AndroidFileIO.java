package com.github.unidbg.file.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.linux.struct.StatFS;
import com.sun.jna.Pointer;

public interface AndroidFileIO extends NewFileIO {

    int SIOCGIFCONF = 0x8912; /* get iface list		*/
    int SIOCGIFFLAGS = 0x8913;		/* get flags			*/

    int fstat(Emulator<?> emulator, StatStructure stat);

    int getdents64(Pointer dirp, int size);

    AndroidFileIO accept(Pointer addr, Pointer addrlen);

    int statfs(StatFS statFS);
}
