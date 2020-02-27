package com.github.unidbg.file.linux;

public interface IOConstants {

    int O_RDONLY = 0;
    int O_WRONLY = 1;
    int O_RDWR = 2;
    int O_CREAT = 0x40;
    int O_EXCL = 0x80;
    int O_APPEND = 0x400;
    int O_NONBLOCK = 0x800;
    int O_DIRECTORY = 0x10000;
    int O_NOFOLLOW = 0x20000;

}
