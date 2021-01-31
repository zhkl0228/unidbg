package com.github.unidbg.ios;

import com.github.unidbg.Family;
import com.github.unidbg.arm.AbstractARM64Emulator;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.file.FileSystem;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.file.ios.DarwinFileSystem;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.Dlfcn;
import com.github.unidbg.spi.LibraryFile;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.sun.jna.Pointer;
import unicorn.UnicornConst;

import java.io.File;
import java.net.URL;
import java.util.Collection;
import java.util.Collections;

public class DarwinARM64Emulator extends AbstractARM64Emulator<DarwinFileIO> {

    protected DarwinARM64Emulator(String processName, File rootDir, Collection<BackendFactory> backendFactories, String... envs) {
        super(processName, rootDir, Family.iOS, backendFactories, envs);
    }

    @Override
    protected FileSystem<DarwinFileIO> createFileSystem(File rootDir) {
        return new DarwinFileSystem(this, rootDir);
    }

    protected void setupTraps() {
        super.setupTraps();

        try {
            int size = 0x10000;
            backend.mem_map(MachO._KERNEL_BASE64, size, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);

            long _COMM_PAGE_MEMORY_SIZE = (MachO._COMM_PAGE64_BASE_ADDRESS+0x038);	// uint64_t max memory size */
            Pointer commPageMemorySize = UnidbgPointer.pointer(this, _COMM_PAGE_MEMORY_SIZE);
            if (commPageMemorySize != null) {
                commPageMemorySize.setLong(0, 0);
            }

            long _COMM_PAGE_NCPUS = (MachO._COMM_PAGE64_BASE_ADDRESS+0x022);	// uint8_t number of configured CPUs
            Pointer commPageNCpus = UnidbgPointer.pointer(this, _COMM_PAGE_NCPUS);
            if (commPageNCpus != null) {
                commPageNCpus.setByte(0, (byte) 1);
            }

            long _COMM_PAGE_ACTIVE_CPUS = (MachO._COMM_PAGE64_BASE_ADDRESS+0x034);	// uint8_t number of active CPUs (hw.activecpu)
            Pointer commPageActiveCpus = UnidbgPointer.pointer(this, _COMM_PAGE_ACTIVE_CPUS);
            if (commPageActiveCpus != null) {
                commPageActiveCpus.setByte(0, (byte) 1);
            }

            long _COMM_PAGE_PHYSICAL_CPUS = (MachO._COMM_PAGE64_BASE_ADDRESS+0x035);	// uint8_t number of physical CPUs (hw.physicalcpu_max)
            Pointer commPagePhysicalCpus = UnidbgPointer.pointer(this, _COMM_PAGE_PHYSICAL_CPUS);
            if (commPagePhysicalCpus != null) {
                commPagePhysicalCpus.setByte(0, (byte) 1);
            }

            long _COMM_PAGE_LOGICAL_CPUS = (MachO._COMM_PAGE64_BASE_ADDRESS+0x036);	// uint8_t number of logical CPUs (hw.logicalcpu_max)
            Pointer commPageLogicalCpus = UnidbgPointer.pointer(this, _COMM_PAGE_LOGICAL_CPUS);
            if (commPageLogicalCpus != null) {
                commPageLogicalCpus.setByte(0, (byte) 1);
            }
        } catch(BackendException ignored) { // hypervisor backend
        }
    }

    @Override
    protected Memory createMemory(UnixSyscallHandler<DarwinFileIO> syscallHandler, String[] envs) {
        return new MachOLoader(this, syscallHandler, envs);
    }

    @Override
    protected Dlfcn createDyld(SvcMemory svcMemory) {
        return new Dyld64((MachOLoader) memory, svcMemory);
    }

    @Override
    protected UnixSyscallHandler<DarwinFileIO> createSyscallHandler(SvcMemory svcMemory) {
        return new ARM64SyscallHandler(svcMemory);
    }

    @Override
    public LibraryFile createURLibraryFile(URL url, String libName) {
        return new URLibraryFile(url, "/usr/lib/" + libName, null, Collections.<String>emptyList());
    }

    @Override
    protected int getPageAlignInternal() {
        return 0x4000;
    }

    @Override
    protected boolean isPaddingArgument() {
        return false;
    }

    @Override
    protected void dumpClass(String className) {
        IClassDumper classDumper = ClassDumper.getInstance(this);
        String classData = classDumper.dumpClass(className);
        System.out.println("dumpClass\n" + classData);
    }

    @Override
    protected void searchClass(String keywords) {
        IClassDumper classDumper = ClassDumper.getInstance(this);
        classDumper.searchClass(keywords);
    }
}
