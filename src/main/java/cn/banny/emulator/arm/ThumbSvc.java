package cn.banny.emulator.arm;

import cn.banny.emulator.Svc;
import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.pointer.UnicornPointer;
import keystone.KeystoneMode;

public abstract class ThumbSvc implements Svc {

    @Override
    public UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        if (svcNumber > 0xff) {
            throw new IllegalStateException();
        }

        return ArmSvc.register(svcMemory, svcNumber, KeystoneMode.ArmThumb);
    }

}
