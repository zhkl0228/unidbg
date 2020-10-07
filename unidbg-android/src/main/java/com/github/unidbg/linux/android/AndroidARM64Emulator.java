package com.github.unidbg.linux.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Family;
import com.github.unidbg.arm.AbstractARM64Emulator;
import com.github.unidbg.file.FileSystem;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.file.linux.LinuxFileSystem;
import com.github.unidbg.linux.ARM64SyscallHandler;
import com.github.unidbg.linux.AndroidElfLoader;
import com.github.unidbg.linux.android.dvm.DalvikVM64;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.spi.Dlfcn;
import com.github.unidbg.spi.LibraryFile;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.unwind.Unwinder;

import java.io.File;
import java.net.URL;

/**
 * android arm emulator
 * Created by zhkl0228 on 2017/5/2.
 */

public class AndroidARM64Emulator extends AbstractARM64Emulator<AndroidFileIO> implements AndroidEmulator {

    @SuppressWarnings("unused")
    public AndroidARM64Emulator() {
        this(null, null);
    }

    public AndroidARM64Emulator(String processName) {
        this(processName, null);
    }

    @Override
    protected FileSystem<AndroidFileIO> createFileSystem(File rootDir) {
        return new LinuxFileSystem(this, rootDir);
    }

    @SuppressWarnings("unused")
    public AndroidARM64Emulator(File rootDir) {
        this(null, rootDir);
    }

    public AndroidARM64Emulator(String processName, File rootDir) {
        super(processName, rootDir, Family.Android64);
    }

    @Override
    protected Memory createMemory(UnixSyscallHandler<AndroidFileIO> syscallHandler, String[] envs) {
        return new AndroidElfLoader(this, syscallHandler);
    }

    @Override
    protected Dlfcn createDyld(SvcMemory svcMemory) {
        return new ArmLD64(backend, svcMemory);
    }

    @Override
    protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
        return new ARM64SyscallHandler(svcMemory);
    }

    private VM createDalvikVMInternal(File apkFile) {
        return new DalvikVM64(this, apkFile);
    }

    @Override
    public LibraryFile createURLibraryFile(URL url, String libName) {
        return new URLibraryFile(url, libName, -1);
    }

    @Override
    protected boolean isPaddingArgument() {
        return true;
    }

    private VM vm;

    @Override
    public final VM createDalvikVM(File apkFile) {
        if (vm != null) {
            throw new IllegalStateException("vm is already created");
        }
        vm = createDalvikVMInternal(apkFile);
        return vm;
    }

    @Override
    public final VM getDalvikVM() {
        return vm;
    }

    @Override
    public Unwinder getUnwinder() {
        return new AndroidARM64Unwinder(this);
    }
}
