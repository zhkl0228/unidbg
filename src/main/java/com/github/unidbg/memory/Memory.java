package com.github.unidbg.memory;

import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.spi.Loader;
import com.github.unidbg.unix.IO;

import java.io.File;
import java.io.IOException;
import java.util.Collection;

@SuppressWarnings("unused")
public interface Memory extends IO, Loader, StackMemory {

    long HEAP_BASE = 0x8048000;
    long STACK_BASE = 0xc0000000L;
    int STACK_SIZE_OF_PAGE = 512; // 2M

    long MMAP_BASE = 0x40000000L;

    UnicornPointer allocateStack(int size);
    UnicornPointer pointer(long address);
    void setStackPoint(long sp);
    long getStackPoint();
    long getStackBase();
    int getStackSize();

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
