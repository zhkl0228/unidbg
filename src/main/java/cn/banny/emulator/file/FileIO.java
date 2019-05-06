package cn.banny.emulator.file;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.ios.struct.kernel.StatFS;
import cn.banny.emulator.memory.MemoryMap;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

import java.io.IOException;
import java.util.Map;

public interface FileIO {

    int O_RDONLY = 0;
    int O_WRONLY = 1;
    int O_RDWR = 2;
    int O_CREAT = 0x40;
    int O_APPEND = 0x400;
    int O_NONBLOCK = 0x800;
    int O_NOFOLLOW = 0x20000;

    int SEEK_SET = 0;
    int SEEK_CUR = 1;
    int SEEK_END = 2;

    void close();

    int write(byte[] data);

    int read(Unicorn unicorn, Pointer buffer, int count);

    int fstat(Emulator emulator, Unicorn unicorn, Pointer stat);
    int fstat(StatStructure stat);

    int fcntl(int cmd, int arg);

    int ioctl(Emulator emulator, long request, long argp);

    FileIO dup2();

    int connect(Pointer addr, int addrlen);

    int setsockopt(int level, int optname, Pointer optval, int optlen);

    int sendto(byte[] data, int flags, Pointer dest_addr, int addrlen);

    int lseek(int offset, int whence);

    int ftruncate(int length);

    int getpeername(Pointer addr, Pointer addrlen);

    int shutdown(int how);

    int getsockopt(int level, int optname, Pointer optval, Pointer optlen);

    int getsockname(Pointer addr, Pointer addrlen);

    int mmap2(Unicorn unicorn, long addr, int aligned, int prot, int offset, int length, Map<Long, MemoryMap> memoryMap) throws IOException;

    int llseek(long offset_high, long offset_low, Pointer result, int whence);

    int getdents64(Pointer dirp, int count);

    int recvfrom(Unicorn unicorn, Pointer buf, int len, int flags, Pointer src_addr, Pointer addrlen);

    int fstatfs(StatFS statFS);
}
