package cn.banny.emulator.ios;

import cn.banny.emulator.unix.UnixSyscallHandler;
import cn.banny.emulator.arm.AbstractARMEmulator;
import cn.banny.emulator.linux.android.dvm.VM;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.spi.Dlfcn;
import cn.banny.emulator.spi.LibraryFile;

import java.io.File;
import java.net.URL;

public class DarwinARMEmulator extends AbstractARMEmulator {

    public DarwinARMEmulator() {
        this(null);
    }

    public DarwinARMEmulator(String processName) {
        super(processName);
    }

    @Override
    protected Memory createMemory(UnixSyscallHandler syscallHandler) {
        return new MachOLoader(this, syscallHandler);
    }

    @Override
    protected Dlfcn createDyld(SvcMemory svcMemory) {
        return new Dyld((MachOLoader) memory, svcMemory);
    }

    @Override
    protected UnixSyscallHandler createSyscallHandler(SvcMemory svcMemory) {
        return new ARM32SyscallHandler(svcMemory);
    }

    @Override
    public VM createDalvikVM(File apkFile) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getLibraryExtension() {
        return ".dylib";
    }

    @Override
    public String getLibraryPath() {
        return "/ios/lib/";
    }

    @Override
    public LibraryFile createURLibraryFile(URL url, String libName) {
        return new URLibraryFile(url, libName, null);
    }
}
