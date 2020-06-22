package com.github.unidbg.ios;

import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.unix.UnixSyscallHandler;

abstract class DarwinSyscallHandler extends UnixSyscallHandler<DarwinFileIO> implements SyscallHandler<DarwinFileIO>, DarwinSyscall  {

    final long bootTime = System.currentTimeMillis();

}
