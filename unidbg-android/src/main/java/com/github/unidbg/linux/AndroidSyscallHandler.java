package com.github.unidbg.linux;

import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.unix.UnixSyscallHandler;

abstract class AndroidSyscallHandler extends UnixSyscallHandler<AndroidFileIO> implements SyscallHandler<AndroidFileIO> {
}
