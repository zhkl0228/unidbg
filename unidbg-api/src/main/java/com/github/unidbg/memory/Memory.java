package com.github.unidbg.memory;

import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.Loader;
import com.github.unidbg.unix.IO;

import java.io.File;
import java.io.IOException;
import java.util.Collection;

@SuppressWarnings("unused")
public interface Memory extends IO, Loader, StackMemory {

    long HEAP_BASE = 0x8048000;
    long STACK_BASE = 0xc0000000L;
    int STACK_SIZE_OF_PAGE = 256; // 1024k

    long MMAP_BASE = 0x40000000L;

    UnidbgPointer allocateStack(int size);
    UnidbgPointer pointer(long address);
    void setStackPoint(long sp);
    long getStackPoint();
    long getStackBase();
    int getStackSize();

    long mmap2(long start, int length, int prot, int flags, int fd, int offset);
    int mprotect(long address, int length, int prot);
    int brk(long address);

    MemoryBlock malloc(int length);
    MemoryBlock malloc(int length, boolean runtime);
    UnidbgPointer mmap(int length, int prot);
    int munmap(long start, int length);

    /**
     * set errno
     */
    void setErrno(int errno);

    File dumpHeap() throws IOException;
    File dumpStack() throws IOException;

    Collection<MemoryMap> getMemoryMap();

}
