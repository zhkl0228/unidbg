package com.github.unidbg.memory;

import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.Loader;
import com.github.unidbg.unix.IO;

import java.util.Collection;

@SuppressWarnings("unused")
public interface Memory extends IO, Loader, StackMemory {

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

    /**
     * 分配内存
     * @param length 大小
     * @param runtime <code>true</code>表示使用mmap按页大小分配，相应的调用MemoryBlock.free方法则使用munmap释放，<code>false</code>表示使用libc.malloc分配，相应的调用MemoryBlock.free方法则使用libc.free释放
     */
    MemoryBlock malloc(int length, boolean runtime);
    UnidbgPointer mmap(int length, int prot);
    int munmap(long start, int length);

    /**
     * set errno
     */
    void setErrno(int errno);

    Collection<MemoryMap> getMemoryMap();

}
