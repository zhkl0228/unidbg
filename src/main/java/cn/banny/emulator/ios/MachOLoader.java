package cn.banny.emulator.ios;

import cn.banny.emulator.*;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.MemoryBlock;
import unicorn.WriteHook;

import java.io.File;
import java.io.IOException;
import java.util.Collection;

public class MachOLoader extends AbstractLoader implements Memory, Loader {

    MachOLoader(Emulator emulator, AbstractSyscallHandler syscallHandler) {
        super(emulator, syscallHandler);
    }

    @Override
    protected Module loadInternal(LibraryFile libraryFile, WriteHook unpackHook, boolean forceCallInit) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public int mmap2(long start, int length, int prot, int flags, int fd, int offset) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int brk(long address) {
        throw new UnsupportedOperationException();
    }

    @Override
    public MemoryBlock malloc(int length, boolean runtime) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setErrno(int errno) {
    }

    @Override
    public File dumpHeap() throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] unpack(File elfFile) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Module findModuleByAddress(long address) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Module findModule(String soName) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Module dlopen(String filename) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Module dlopen(String filename, boolean calInit) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean dlclose(long handle) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Symbol dlsym(long handle, String symbol) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Collection<Module> getLoadedModules() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getMaxLengthLibraryName() {
        throw new UnsupportedOperationException();
    }

    @Override
    public long getMaxSizeOfLibrary() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void runThread(int threadId) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void runLastThread() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean hasThread(int threadId) {
        throw new UnsupportedOperationException();
    }

}
