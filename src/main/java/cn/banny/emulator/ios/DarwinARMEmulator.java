package cn.banny.emulator.ios;

import cn.banny.emulator.AbstractSyscallHandler;
import cn.banny.emulator.Dlfcn;
import cn.banny.emulator.arm.AbstractARMEmulator;
import cn.banny.emulator.linux.android.dvm.VM;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.SvcMemory;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.UnicornConst;

import java.io.File;
import java.nio.ByteBuffer;

public class DarwinARMEmulator extends AbstractARMEmulator {

    public DarwinARMEmulator() {
        this(null);
    }

    public DarwinARMEmulator(String processName) {
        super(processName);

        setupTraps();
    }

    private void setupTraps() {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
            unicorn.mem_map(LR, 0x10000, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
            KeystoneEncoded encoded = keystone.assemble("mov pc, #0");
            byte[] b0 = encoded.getMachineCode();
            ByteBuffer buffer = ByteBuffer.allocate(0x10000);
            // write "mov pc, #0" to all kernel trap addresses so they will throw exception
            for (int i = 0; i < 0x10000; i += 4) {
                buffer.put(b0);
            }
            unicorn.mem_write(LR, buffer.array());
        }
    }

    @Override
    protected Memory createMemory(AbstractSyscallHandler syscallHandler) {
        return new MachOLoader(this, syscallHandler);
    }

    @Override
    protected Dlfcn createDyld(SvcMemory svcMemory) {
        return new Dyld((MachOLoader) memory);
    }

    @Override
    public VM createDalvikVM(File apkFile) {
        throw new UnsupportedOperationException();
    }
}
