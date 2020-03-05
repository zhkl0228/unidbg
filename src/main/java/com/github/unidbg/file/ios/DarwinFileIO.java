package com.github.unidbg.file.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.ios.struct.kernel.StatFS;

public interface DarwinFileIO extends NewFileIO {

    int F_GETPATH = 50; /* return the full path of the fd */

    int fstat(Emulator<?> emulator, StatStructure stat);

    int fstatfs(StatFS statFS);

}
