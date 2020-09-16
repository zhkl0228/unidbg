package com.github.unidbg.unix;

@SuppressWarnings("unused")
public interface IO {

    String STDIN = "stdin";
    int FD_STDIN = 0;

    String STDOUT = "stdout";
    int FD_STDOUT = 1;

    String STDERR = "stderr";
    int FD_STDERR = 2;

    int S_IFREG    = 0x8000;   // regular file
    int S_IFDIR    = 0x4000;   // directory
    int S_IFCHR    = 0x2000;   // character device
    int S_IFLNK    = 0xa000;   // symbolic link
    int S_IFSOCK   = 0xc000;   // socket

    int AT_FDCWD = -100;

}
