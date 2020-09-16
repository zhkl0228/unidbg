package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Svc;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnicornPointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;

import java.util.Arrays;

public abstract class Arm64Svc implements Svc {

    @Override
    public UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        return register(svcMemory, svcNumber);
    }

    private static UnicornPointer register(SvcMemory svcMemory, int svcNumber) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
            KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                    "svc #0x" + Integer.toHexString(svcNumber),
                    "ret"));
            byte[] code = encoded.getMachineCode();
            UnicornPointer pointer = svcMemory.allocate(code.length, "Arm64Svc");
            pointer.write(0, code, 0, code.length);
            return pointer;
        }
    }

    @Override
    public void handleCallback(Emulator<?> emulator) {
    }

}
