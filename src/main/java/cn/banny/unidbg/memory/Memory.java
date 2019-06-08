package cn.banny.unidbg.memory;

import cn.banny.unidbg.spi.Loader;
import cn.banny.unidbg.unix.IO;
import cn.banny.unidbg.pointer.UnicornPointer;

import java.io.File;
import java.io.IOException;
import java.util.Collection;

public interface Memory extends IO, Loader {

    long HEAP_BASE = 0x8048000;
    long STACK_BASE = 0xc0000000L;
    int STACK_SIZE_OF_PAGE = 512; // 2M

    long MMAP_BASE = 0x40000000L;

    UnicornPointer allocateStack(int size);
    UnicornPointer writeStackString(String str);
    UnicornPointer writeStackBytes(byte[] data);
    UnicornPointer pointer(long address);
    void setStackPoint(long sp);
    long getStackPoint();

    void setCallInitFunction();

    long mmap2(long start, int length, int prot, int flags, int fd, int offset);
    int mprotect(long address, int length, int prot);
    int brk(long address);

    MemoryBlock malloc(int length);
    MemoryBlock malloc(int length, boolean runtime);
    UnicornPointer mmap(int length, int prot);
    int munmap(long start, int length);

    /**
     * set errno
     */
    void setErrno(int errno);

    File dumpHeap() throws IOException;
    File dumpStack() throws IOException;

    Collection<MemoryMap> getMemoryMap();

}
