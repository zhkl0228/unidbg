package cn.banny.unidbg.arm;

import cn.banny.unidbg.Svc;
import cn.banny.unidbg.memory.SvcMemory;
import cn.banny.unidbg.pointer.UnicornPointer;
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
