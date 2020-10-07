package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Svc;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import keystone.KeystoneMode;

public abstract class ThumbSvc implements Svc {

    @Override
    public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        if (svcNumber > 0xff) {
            throw new IllegalStateException();
        }

        return ArmSvc.register(svcMemory, svcNumber, KeystoneMode.ArmThumb);
    }

    @Override
    public void handleCallback(Emulator<?> emulator) {
    }

}
