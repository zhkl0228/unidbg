package com.github.unidbg.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.sun.jna.Pointer;

import java.io.IOException;

public interface FileIO {

    int SEEK_SET = 0;
    int SEEK_CUR = 1;
    int SEEK_END = 2;

    void close();

    int write(byte[] data);

    int read(Backend backend, Pointer buffer, int count);

    int fcntl(Emulator<?> emulator, int cmd, long arg);

    int ioctl(Emulator<?> emulator, long request, long argp);

    FileIO dup2();

    int connect(Pointer addr, int addrlen);

    int bind(Pointer addr, int addrlen);

    int listen(int backlog);

    int setsockopt(int level, int optname, Pointer optval, int optlen);

    int sendto(byte[] data, int flags, Pointer dest_addr, int addrlen);

    int lseek(int offset, int whence);

    int ftruncate(int length);

    int getpeername(Pointer addr, Pointer addrlen);

    int shutdown(int how);

    int getsockopt(int level, int optname, Pointer optval, Pointer optlen);

    int getsockname(Pointer addr, Pointer addrlen);

    long mmap2(Emulator<?> emulator, long addr, int aligned, int prot, int offset, int length) throws IOException;

    int llseek(long offset, Pointer result, int whence);

    int recvfrom(Backend backend, Pointer buf, int len, int flags, Pointer src_addr, Pointer addrlen);

    String getPath();
}
