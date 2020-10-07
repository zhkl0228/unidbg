package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Svc;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;

import java.util.Arrays;

public abstract class ArmSvc implements Svc {

    @Override
    public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        return register(svcMemory, svcNumber, KeystoneMode.Arm);
    }

    static UnidbgPointer register(SvcMemory svcMemory, int svcNumber, KeystoneMode mode) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, mode)) {
            KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                    "svc #0x" + Integer.toHexString(svcNumber),
                    "bx lr"));
            byte[] code = encoded.getMachineCode();
            UnidbgPointer pointer = svcMemory.allocate(code.length, "ArmSvc");
            pointer.write(0, code, 0, code.length);
            return pointer;
        }
    }

    @Override
    public void handleCallback(Emulator<?> emulator) {
    }

}
