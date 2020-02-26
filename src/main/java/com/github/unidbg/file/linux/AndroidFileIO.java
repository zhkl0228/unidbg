package com.github.unidbg.file.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.NewFileIO;

public interface AndroidFileIO extends NewFileIO {

    int SIOCGIFCONF = 0x8912;

    int fstat(Emulator<?> emulator, StatStructure stat);

}
