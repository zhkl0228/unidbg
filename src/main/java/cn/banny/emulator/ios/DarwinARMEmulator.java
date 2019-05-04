package cn.banny.emulator.ios;

import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.unix.UnixSyscallHandler;
import cn.banny.emulator.arm.AbstractARMEmulator;
import cn.banny.emulator.linux.android.dvm.VM;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.spi.Dlfcn;
import cn.banny.emulator.spi.LibraryFile;
import com.sun.jna.Pointer;

import java.io.File;
import java.net.URL;

public class DarwinARMEmulator extends AbstractARMEmulator {

    private static final long _COMM_PAGE32_BASE_ADDRESS = (0xffff4000L);
    private static final long _COMM_PAGE64_BASE_ADDRESS = (0x0000000fffffc000L) /* In TTBR0 */;

    public DarwinARMEmulator() {
        this(null);
    }

    public DarwinARMEmulator(String processName) {
        super(processName);
    }

    @Override
    protected void setupTraps() {
        super.setupTraps();

        long _COMM_PAGE_MEMORY_SIZE = ((getPointerSize() == 4 ? _COMM_PAGE32_BASE_ADDRESS : _COMM_PAGE64_BASE_ADDRESS) +0x038);	// uint64_t max memory size */
        Pointer commPageMemorySize = UnicornPointer.pointer(this, _COMM_PAGE_MEMORY_SIZE);
        if (commPageMemorySize != null) {
            commPageMemorySize.setLong(0, 0);
        }
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
