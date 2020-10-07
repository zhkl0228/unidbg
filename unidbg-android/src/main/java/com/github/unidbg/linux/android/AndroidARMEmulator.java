package com.github.unidbg.linux.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Family;
import com.github.unidbg.arm.AbstractARMEmulator;
import com.github.unidbg.file.FileSystem;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.file.linux.LinuxFileSystem;
import com.github.unidbg.linux.ARM32SyscallHandler;
import com.github.unidbg.linux.AndroidElfLoader;
import com.github.unidbg.linux.android.dvm.DalvikVM;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.spi.Dlfcn;
import com.github.unidbg.spi.LibraryFile;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.unwind.Unwinder;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.net.URL;
import java.util.Arrays;

/**
 * android arm emulator
 * Created by zhkl0228 on 2017/5/2.
 */

public class AndroidARMEmulator extends AbstractARMEmulator<AndroidFileIO> implements AndroidEmulator {

    private static final Log log = LogFactory.getLog(AndroidARMEmulator.class);

    public AndroidARMEmulator() {
        this(null, null);
    }

    public AndroidARMEmulator(String processName) {
        this(processName, null);
    }

    public AndroidARMEmulator(File rootDir) {
        this(null, rootDir);
    }

    public AndroidARMEmulator(String processName, File rootDir) {
        super(processName, rootDir, Family.Android32);
    }

    @Override
    protected FileSystem<AndroidFileIO> createFileSystem(File rootDir) {
        return new LinuxFileSystem(this, rootDir);
    }

    @Override
    protected Memory createMemory(UnixSyscallHandler<AndroidFileIO> syscallHandler, String[] envs) {
        return new AndroidElfLoader(this, syscallHandler);
    }

    @Override
    protected Dlfcn createDyld(SvcMemory svcMemory) {
        return new ArmLD(backend, svcMemory);
    }

    @Override
    protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
        return new ARM32SyscallHandler(svcMemory);
    }

    private VM createDalvikVMInternal(File apkFile) {
        return new DalvikVM(this, apkFile);
    }

    /**
     * https://github.com/lunixbochs/usercorn/blob/master/go/arch/arm/linux.go
     */
    @Override
    protected final void setupTraps() {
        super.setupTraps();

        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
            KeystoneEncoded encoded = keystone.assemble("bx lr", 0xffff0fa0);
            byte[] __kuser_memory_barrier = encoded.getMachineCode();

            encoded = keystone.assemble(Arrays.asList(
                    "dmb sy",
                    "ldrex r3, [r2]",
                    "subs r3, r3, r0",
                    "strexeq r3, r1, [r2]",
                    "teqeq r3, #1",
                    "beq #0xffff0fc4",
                    "rsbs r0, r3, #0",
                    "b #0xffff0fa0"), 0xffff0fc0);
            byte[] __kuser_cmpxchg = encoded.getMachineCode();
            memory.pointer(0xffff0fa0L).write(__kuser_memory_barrier);
            memory.pointer(0xffff0fc0L).write(__kuser_cmpxchg);

            if (log.isDebugEnabled()) {
                log.debug("__kuser_memory_barrier");
                for (int i = 0; i < __kuser_memory_barrier.length; i += 4) {
                    printAssemble(System.err, 0xffff0fa0L + i, 4);
                }
                log.debug("__kuser_cmpxchg");
                for (int i = 0; i < __kuser_cmpxchg.length; i += 4) {
                    printAssemble(System.err, 0xffff0fc0L + i, 4);
                }
            }
        }
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
        return new AndroidARMUnwinder(this);
    }

}
