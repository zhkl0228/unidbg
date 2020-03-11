package com.github.unidbg.file.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.NewFileIO;
import com.sun.jna.Pointer;

public interface AndroidFileIO extends NewFileIO {

    int SIOCGIFCONF = 0x8912; /* get iface list		*/

    int fstat(Emulator<?> emulator, StatStructure stat);

    int getdents64(Pointer dirp, int size);

    AndroidFileIO accept(Pointer addr, Pointer addrlen);

}
