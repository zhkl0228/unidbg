package com.github.unidbg.file.ios;

public interface IOConstants {

    int O_RDONLY = 0x0000; /* open for reading only */
    int O_WRONLY = 0x0001; /* open for writing only */
    int O_RDWR = 0x0002; /* open for reading and writing */
    int O_NONBLOCK = 0x0004; /* no delay */
    int O_APPEND = 0x0008; /* set append mode */
    int O_CREAT = 0x0200; /* create if nonexistant */
    int O_EXCL = 0x0800; /* error if already exists */

    int O_DIRECTORY = 0x100000;

}
