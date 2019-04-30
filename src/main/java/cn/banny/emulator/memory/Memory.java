package cn.banny.emulator.memory;

import cn.banny.emulator.spi.Loader;
import cn.banny.emulator.unix.IO;
import cn.banny.emulator.pointer.UnicornPointer;

import java.io.File;
import java.io.IOException;

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

    void setCallInitFunction();

    int mmap2(long start, int length, int prot, int flags, int fd, int offset);
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

}
