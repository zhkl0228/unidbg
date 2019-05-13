package cn.banny.emulator.linux.android;

import cn.banny.emulator.unix.UnixSyscallHandler;
import cn.banny.emulator.arm.ARMEmulator;
import cn.banny.emulator.arm.AbstractARM64Emulator;
import cn.banny.emulator.linux.ARM64SyscallHandler;
import cn.banny.emulator.linux.AndroidElfLoader;
import cn.banny.emulator.linux.android.dvm.DalvikVM64;
import cn.banny.emulator.linux.android.dvm.VM;
import cn.banny.emulator.spi.Dlfcn;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.spi.LibraryFile;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.UnicornConst;

import java.io.File;
import java.net.URL;
import java.nio.ByteBuffer;

/**
 * android arm emulator
 * Created by zhkl0228 on 2017/5/2.
 */

public class AndroidARM64Emulator extends AbstractARM64Emulator implements ARMEmulator {

    public AndroidARM64Emulator() {
        this(null);
    }

    public AndroidARM64Emulator(String processName) {
        super(processName);

        setupTraps();
    }

    @Override
    protected Memory createMemory(UnixSyscallHandler syscallHandler) {
        return new AndroidElfLoader(this, syscallHandler);
    }

    @Override
    protected Dlfcn createDyld(SvcMemory svcMemory) {
        return new ArmLD64(unicorn, svcMemory);
    }

    @Override
    protected UnixSyscallHandler createSyscallHandler(SvcMemory svcMemory) {
        return new ARM64SyscallHandler(svcMemory);
    }

    @Override
    public VM createDalvikVM(File apkFile) {
        return new DalvikVM64(this, apkFile);
    }

    /**
     * https://github.com/lunixbochs/usercorn/blob/master/go/arch/arm/linux.go
     */
    private void setupTraps() {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
            unicorn.mem_map(LR, 0x10000, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
            KeystoneEncoded encoded = keystone.assemble("b #0");
            byte[] b0 = encoded.getMachineCode();
            ByteBuffer buffer = ByteBuffer.allocate(0x10000);
            for (int i = 0; i < 0x10000; i += b0.length) {
                buffer.put(b0);
            }
            unicorn.mem_write(LR, buffer.array());
        }
    }

    @Override
    public String getLibraryExtension() {
        return ".so";
    }

    @Override
    public String getLibraryPath() {
        return "/android/lib/arm64-v8a/";
    }

    @Override
    public LibraryFile createURLibraryFile(URL url, String libName) {
        return new URLibraryFile(url, libName, -1);
    }
}
